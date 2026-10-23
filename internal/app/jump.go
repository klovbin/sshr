package app

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// ProxyCommandName is the hidden CLI command sshr runs as an ssh
// ProxyCommand to reach a host through saved jump hosts
const ProxyCommandName = "__proxy"

// maxJumpDepth stops a jump chain that points back at itself
const maxJumpDepth = 8

// SplitJump turns "a,b" into ["a", "b"], dropping empty parts
func SplitJump(spec string) []string {
	var out []string
	for _, p := range strings.Split(spec, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// hopRe is one jump hop: a saved host name or ID, or [user@]host[:port]
// with an IPv6 address in brackets, nothing a shell, ssh config or a
// %-token would read as more than a name, the hops end up in ProxyCommand,
// which ssh runs with the shell, and in the ssh config export
var hopRe = regexp.MustCompile(`^(?:[A-Za-z0-9._][A-Za-z0-9._-]*@)?(?:[A-Za-z0-9._][A-Za-z0-9._-]*|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?$`)

// normalizeJump checks a jump spec and returns it in canonical "a,b" form
func normalizeJump(spec string) (string, error) {
	parts := SplitJump(spec)
	for _, p := range parts {
		if !hopRe.MatchString(p) {
			return "", fmt.Errorf("invalid jump host %q, use a saved host name or ID, or [user@]host[:port]", p)
		}
	}
	return strings.Join(parts, ","), nil
}

// ParseHop reads a free-form jump hop: [user@]host[:port], with IPv6 in
// brackets ([::1]:22)
func ParseHop(spec string) (*Host, error) {
	h := &Host{Name: spec, Port: 22}
	rest := spec
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		h.User, rest = rest[:i], rest[i+1:]
	}
	if strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "]")
		if end < 0 {
			return nil, fmt.Errorf("invalid jump host %q", spec)
		}
		h.Host, rest = rest[1:end], rest[end+1:]
		if rest != "" && !strings.HasPrefix(rest, ":") {
			return nil, fmt.Errorf("invalid jump host %q", spec)
		}
		rest = strings.TrimPrefix(rest, ":")
	} else if i := strings.LastIndex(rest, ":"); i >= 0 && strings.Count(rest, ":") == 1 {
		h.Host, rest = rest[:i], rest[i+1:]
	} else {
		h.Host, rest = rest, ""
	}
	if rest != "" {
		p, err := ParsePort(rest)
		if err != nil {
			return nil, fmt.Errorf("invalid port in jump host %q", spec)
		}
		h.Port = p
	}
	if h.Host == "" {
		return nil, fmt.Errorf("invalid jump host %q", spec)
	}
	return h, nil
}

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
	// with -J the ssh for each hop inherits the askpass of this host, a
	// bastion that asks for a password would get this host's saved one,
	// sshr as ProxyCommand starts each hop with that environment removed
	if !anySaved && !h.PasswordFromSshr() {
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
	h.route = ""
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
