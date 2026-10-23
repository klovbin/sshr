package hosts

import (
	"fmt"
	"regexp"
	"strings"
)

// Forward is a named port forward saved with a host, like "db" for
// -L 5432:localhost:5432
type Forward struct {
	Name string `json:"name"`
	// Kind is "L" (local port to a remote address), "R" (remote port to a
	// local address) or "D" (local SOCKS proxy)
	Kind string `json:"kind"`
	// Spec is what ssh takes after -L/-R/-D, [bind:]port:host:hostport for L
	// and R, [bind:]port for D
	Spec string `json:"spec"`
}

var forwardName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)

// Args returns the ssh options for f
func (f Forward) Args() []string {
	return []string{"-" + f.Kind, f.Spec}
}

// String is the form used in the CLI and the host form, "db -L 5432:localhost:5432"
func (f Forward) String() string {
	return f.Name + " -" + f.Kind + " " + f.Spec
}

// ParseForward reads "name -L spec", "name -R spec" or "name -D spec"
func ParseForward(s string) (Forward, error) {
	fields := strings.Fields(s)
	if len(fields) != 3 || len(fields[1]) != 2 || fields[1][0] != '-' {
		return Forward{}, fmt.Errorf("forward %q: expected \"name -L|-R|-D spec\"", s)
	}
	f := Forward{Name: fields[0], Kind: fields[1][1:], Spec: fields[2]}
	return f, f.Check()
}

// ParseForwards reads one forward per line, skipping empty lines
func ParseForwards(text string) ([]Forward, error) {
	var out []Forward
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f, err := ParseForward(line)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// FormatForwards is the inverse of ParseForwards
func FormatForwards(fs []Forward) string {
	lines := make([]string, len(fs))
	for i, f := range fs {
		lines[i] = f.String()
	}
	return strings.Join(lines, "\n")
}

// Check refuses a forward ssh would read wrongly, the spec reaches its
// command line
func (f Forward) Check() error {
	if !forwardName.MatchString(f.Name) {
		return fmt.Errorf("forward name %q: use letters, digits, '.', '_' or '-'", f.Name)
	}
	parts := splitSpec(f.Spec)
	switch f.Kind {
	case "L", "R":
		// port:host:hostport or bind:port:host:hostport
		if len(parts) == 4 {
			parts = parts[1:]
		}
		if len(parts) != 3 || parts[1] == "" {
			return fmt.Errorf("forward %s: -%s needs [bind:]port:host:hostport, got %q", f.Name, f.Kind, f.Spec)
		}
		if _, err := ParsePort(parts[0]); err != nil {
			return fmt.Errorf("forward %s: bad port %q", f.Name, parts[0])
		}
		if _, err := ParsePort(parts[2]); err != nil {
			return fmt.Errorf("forward %s: bad port %q", f.Name, parts[2])
		}
	case "D":
		if len(parts) == 2 {
			parts = parts[1:]
		}
		if len(parts) != 1 {
			return fmt.Errorf("forward %s: -D needs [bind:]port, got %q", f.Name, f.Spec)
		}
		if _, err := ParsePort(parts[0]); err != nil {
			return fmt.Errorf("forward %s: bad port %q", f.Name, parts[0])
		}
	default:
		return fmt.Errorf("forward %s: kind must be L, R or D, got %q", f.Name, f.Kind)
	}
	return nil
}

// splitSpec splits a forward spec on ':' and keeps [IPv6] addresses whole
func splitSpec(spec string) []string {
	var parts []string
	cur := strings.Builder{}
	depth := 0
	for _, r := range spec {
		switch {
		case r == '[':
			depth++
		case r == ']':
			depth--
		case r == ':' && depth == 0:
			parts = append(parts, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteRune(r)
	}
	return append(parts, cur.String())
}

// checkForwards validates a host's forwards and refuses duplicate names
func checkForwards(fs []Forward) error {
	seen := map[string]bool{}
	for _, f := range fs {
		if err := f.Check(); err != nil {
			return err
		}
		if seen[f.Name] {
			return fmt.Errorf("forward name %q is used twice", f.Name)
		}
		seen[f.Name] = true
	}
	return nil
}

// FindForwards picks forwards by name, "all" picks every one
func FindForwards(fs []Forward, names []string) ([]Forward, error) {
	if len(names) == 1 && names[0] == "all" {
		return fs, nil
	}
	var out []Forward
	for _, n := range names {
		found := false
		for _, f := range fs {
			if f.Name == n {
				out = append(out, f)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("no forward named %q", n)
		}
	}
	return out, nil
}
