package app

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ProxyCommandName is the hidden CLI command sshr runs as an ssh
// ProxyCommand to reach a host through saved jump hosts
const ProxyCommandName = "__proxy"

// maxJumpDepth stops a jump chain that points back at itself
const maxJumpDepth = 8

// resolveHop returns the saved host a jump part names, or a host built from
// [user@]host[:port] when nothing is saved under that name
func (s *Store) resolveHop(part string) (h *Host, saved bool, err error) {
	found, err := s.Find(part)
	if err == nil {
		return found, true, nil
	}
	var amb *AmbiguousError
	if errors.As(err, &amb) {
		return nil, false, fmt.Errorf("jump host %q matches %d saved hosts, use its ID", part, len(amb.Hosts))
	}
	h, err = ParseHop(part)
	return h, false, err
}

// JumpArgs returns the ssh options that route a connection to h through
// h.Jump, plain hops go to ssh as -J, if any hop is a saved host, ssh runs
// sshr itself as ProxyCommand instead, because -J would not pass that hop's
// key or password
func (s *Store) JumpArgs(h *Host) ([]string, error) {
	// the host file may come from another device or an older version
	spec, err := normalizeJump(h.Via())
	if err != nil {
		return nil, err
	}
	parts := SplitJump(spec)
	if len(parts) == 0 {
		return nil, nil
	}
	anySaved := false
	for _, p := range parts {
		_, saved, err := s.resolveHop(p)
		if err != nil {
			return nil, err
		}
		anySaved = anySaved || saved
	}
	// with -J the ssh for each hop inherits the askpass and the agent of
	// this host, a bastion that asks for a password would get this host's
	// saved one, and every hop would be offered a key kept in sshr, sshr as
	// ProxyCommand starts each hop with that environment removed
	if !anySaved && !h.PasswordFromSshr() && !h.ServedByAgent() {
		return []string{"-J", strings.Join(parts, ",")}, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	// ssh expands %-tokens in ProxyCommand, so a literal % must be doubled
	exe = strings.ReplaceAll(exe, "%", "%%")
	// the hops are checked by hopRe, quoting them as well keeps the shell
	// out even if that check is ever loosened
	cmd := fmt.Sprintf("%q %s %s %%h %%p", exe, ProxyCommandName, shQuote(strings.Join(parts, ",")))
	return []string{"-o", "ProxyCommand=" + cmd}, nil
}

// ConnectArgs is SSHArgs plus the jump options for h, a host with a
// Gateway is checked first and goes through it when down directly
func (s *Store) ConnectArgs(h *Host) ([]string, error) {
	return s.connectArgs(h, true)
}

// DirectArgs is ConnectArgs without the check of a host with a Gateway,
// the options of the direct way, for showing a command without waiting
// on the network
func (s *Store) DirectArgs(h *Host) ([]string, error) {
	return s.connectArgs(h, false)
}

func (s *Store) connectArgs(h *Host, check bool) ([]string, error) {
	// the host file may come from another device or an older version
	if err := checkAddress(h.Host); err != nil {
		return nil, err
	}
	h.RouteViaGateway(false)
	if check {
		pickRoute(h)
	}
	jump, err := s.JumpArgs(h)
	if err != nil {
		return nil, err
	}
	args := append(SSHArgs(h), s.vaultKeyArgs(h)...)
	args = append(args, s.agentArgs(h)...)
	args = append(args, s.reuseArgs(h)...)
	return append(args, jump...), nil
}

// ProxyHop prepares the ssh command line that ProxyCommand runs to reach
// targetHost:targetPort through the last hop of chain, the hops before it
// become that hop's own jump, with a single saved hop its own Jump setting
// is used, so jump hosts can be chained by saving them that way
func (s *Store) ProxyHop(chain, targetHost, targetPort string) (*Host, []string, error) {
	depth, _ := strconv.Atoi(os.Getenv("SSHR_JUMP_DEPTH"))
	if depth >= maxJumpDepth {
		return nil, nil, fmt.Errorf("jump chain is longer than %d hops (does it point back at itself?)", maxJumpDepth)
	}
	os.Setenv("SSHR_JUMP_DEPTH", strconv.Itoa(depth+1))

	parts := SplitJump(chain)
	if len(parts) == 0 {
		return nil, nil, errors.New("empty jump chain")
	}
	last, prev := parts[len(parts)-1], parts[:len(parts)-1]
	hop, _, err := s.resolveHop(last)
	if err != nil {
		return nil, nil, err
	}
	hopCopy := *hop
	if len(prev) > 0 {
		hopCopy.Jump = strings.Join(prev, ",")
	}
	args, err := s.ConnectArgs(&hopCopy)
	if err != nil {
		return nil, nil, err
	}
	if os.Getenv("SSHR_BATCH") == "1" {
		if hopCopy.PasswordMode == PasswordAsk {
			return nil, nil, fmt.Errorf("jump host %s asks for its password every time, there is no terminal to ask in", hopCopy.Name)
		}
		if !hopCopy.PasswordFromSshr() {
			args = append(args, "-o", "BatchMode=yes")
		}
	}
	args = append(args, "-W", hostPort(targetHost, targetPort), "--", hopCopy.Dest())
	return &hopCopy, args, nil
}

// hostPort joins host and port for ssh -W, bracketing IPv6 addresses
func hostPort(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}
