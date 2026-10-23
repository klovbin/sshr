package hosts

import (
	"fmt"
	"regexp"
	"strings"
)

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

// NormalizeJump checks a jump spec and returns it in canonical "a,b" form
func NormalizeJump(spec string) (string, error) {
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
