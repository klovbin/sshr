package hosts

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	maxTags   = 20
	maxTagLen = 32
)

var tagRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// SplitTags reads tags typed as "prod, db" or "prod db"
func SplitTags(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
}

// CleanTags lower-cases, drops a leading #, removes duplicates and sorts,
// a tag is letters, digits, ".", "_" and "-", so it reads the same in a
// search, a file name and a shell command
func CleanTags(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, t := range in {
		t = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(t), "#"))
		if t == "" || seen[t] {
			continue
		}
		if len(t) > maxTagLen || !tagRe.MatchString(t) {
			return nil, fmt.Errorf("tag %q: use letters, digits, '.', '_' and '-', up to %d characters", t, maxTagLen)
		}
		seen[t] = true
		out = append(out, t)
	}
	if len(out) > maxTags {
		return nil, fmt.Errorf("a host has at most %d tags", maxTags)
	}
	sort.Strings(out)
	return out, nil
}

// HasTag tells whether h has tag t
func (h *Host) HasTag(t string) bool {
	t = strings.ToLower(strings.TrimPrefix(t, "#"))
	for _, x := range h.Tags {
		if x == t {
			return true
		}
	}
	return false
}

// Matches tells whether h fits a search, every word has to match, "tag:x"
// or "#x" needs the exact tag, any other word is looked for in the name,
// address, user and tags, case does not matter
func (h *Host) Matches(query string) bool {
	for _, w := range strings.Fields(strings.ToLower(query)) {
		if t, ok := strings.CutPrefix(w, "tag:"); ok {
			if !h.HasTag(t) {
				return false
			}
			continue
		}
		if strings.HasPrefix(w, "#") {
			if !h.HasTag(w) {
				return false
			}
			continue
		}
		hay := strings.ToLower(h.Name + " " + h.Host + " " + h.User + " " + strings.Join(h.Tags, " "))
		if !strings.Contains(hay, w) {
			return false
		}
	}
	return true
}

// Filter keeps the hosts that match query, an empty query keeps all
func Filter(hosts []Host, query string) []Host {
	if strings.TrimSpace(query) == "" {
		return hosts
	}
	var out []Host
	for i := range hosts {
		if hosts[i].Matches(query) {
			out = append(out, hosts[i])
		}
	}
	return out
}
