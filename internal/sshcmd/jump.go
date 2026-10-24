package sshcmd

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

// MaxJumpDepth stops a jump chain that points back at itself
const MaxJumpDepth = 8

// ResolveHop returns the saved host a jump part names, or a host built from
// [user@]host[:port] when nothing is saved under that name
func (e Env) ResolveHop(part string) (h *Host, saved bool, err error) {
	found, err := e.Hosts.Find(part)
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
func (e Env) JumpArgs(h *Host) ([]string, error) {
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
		_, saved, err := e.ResolveHop(p)
		if err != nil {
			return nil, err
		}
		anySaved = anySaved || saved
	}
	// with -J the ssh for each hop inherits the askpass and the agent of
	// this host, a bastion that asks for a password would get this host's
	// saved one, and every hop would be offered a key kept in sshr, sshr as
	// ProxyCommand starts each hop with that environment removed, when every
	// host needs a hardware key each hop goes through sshr too, so the rule
	// is checked for it, ssh -J would log the hop in another way
	if !anySaved && !h.PasswordFromSshr() && !h.ServedByAgent() && !hardwareKeyEverywhere() {
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
func (e Env) ConnectArgs(h *Host) ([]string, error) {
	return e.connectArgs(h, true)
}

// DirectArgs is ConnectArgs without the check of a host with a Gateway,
// the options of the direct way, for showing a command without waiting
// on the network
func (e Env) DirectArgs(h *Host) ([]string, error) {
	return e.connectArgs(h, false)
}

func (e Env) connectArgs(h *Host, check bool) ([]string, error) {
	// the host file may come from another device or an older version
	if err := checkAddress(h.Host); err != nil {
		return nil, err
	}
	h.RouteViaGateway(false)
	if check {
		pickRoute(h)
	}
	jump, err := e.JumpArgs(h)
	if err != nil {
		return nil, err
	}
	hwkey := hardwareKeyRequired(h)
	if hwkey {
		if err := CheckHardwareKey(h); err != nil {
			return nil, err
		}
	}
	args := append(SSHArgs(h), e.vaultKeyArgs(h)...)
	args = append(args, e.agentArgs(h)...)
	if hwkey {
		// a shared master connection could have logged in another way
		args = append(args, hardwareKeyArgs...)
	} else {
		args = append(args, e.reuseArgs(h)...)
	}
	return append(args, jump...), nil
}

// ProxyHop prepares the ssh command line that ProxyCommand runs to reach
// targetHost:targetPort through the last hop of chain, the hops before it
// become that hop's own jump, with a single saved hop its own Jump setting
// is used, so jump hosts can be chained by saving them that way
func (e Env) ProxyHop(chain, targetHost, targetPort string) (*Host, []string, error) {
	depth, _ := strconv.Atoi(os.Getenv("SSHR_JUMP_DEPTH"))
	if depth >= MaxJumpDepth {
		return nil, nil, fmt.Errorf("jump chain is longer than %d hops (does it point back at itself?)", MaxJumpDepth)
	}
	os.Setenv("SSHR_JUMP_DEPTH", strconv.Itoa(depth+1))

	parts := SplitJump(chain)
	if len(parts) == 0 {
		return nil, nil, errors.New("empty jump chain")
	}
	last, prev := parts[len(parts)-1], parts[:len(parts)-1]
	hop, _, err := e.ResolveHop(last)
	if err != nil {
		return nil, nil, err
	}
	hopCopy := *hop
	if len(prev) > 0 {
		hopCopy.Jump = strings.Join(prev, ",")
	}
	args, err := e.ConnectArgs(&hopCopy)
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
