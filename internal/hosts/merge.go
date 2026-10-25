package hosts

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
)

// The fields of Host by how MergeThreeWay treats them, a test fails when a
// field is in none, so a new field is not merged by accident
var (
	// mergeAccess move as one unit from one side: a password or key goes
	// with a destination and must never meet the destination of the other
	// side, the unknown keys a newer sshr wrote go with them
	mergeAccess = []string{"Host", "Port", "User", "Jump", "Gateway", "PasswordMode", "Password", "KeyMode", "KeyPub", "extra"}
	// mergeField merge one by one
	mergeField = []string{"Name", "Session"}
	// mergeSet merge by element, Tags as a set, Forwards by name
	mergeSet = []string{"Tags", "Forwards"}
	// mergeKept are not compared, they belong to this device or do not
	// travel in sync, the local value stays and Import decides on them
	mergeKept = []string{"ID", "Key", "KeyData", "KeyPassphrase", "KeySealed", "KeyRef", "Agent", "AgentKey",
		"PasswordRef", "PasswordSealed", "PlainPassword", "CreatedAt", "LastConnected", "Rev", "route", "format"}
)

// access is the access group of a host, compared as one value
type access struct {
	Host, User, Jump, Gateway, PasswordMode, Password, KeyMode, KeyPub string
	Port                                                               int
	Extra                                                              string
}

func accessOf(h Host) access {
	return access{Host: h.Host, User: h.User, Jump: h.Jump, Gateway: h.Gateway, PasswordMode: h.PasswordMode,
		Password: h.Password, KeyMode: h.KeyMode, KeyPub: h.KeyPub, Port: h.Port, Extra: syncedExtra(h)}
}

// syncedExtra is the unknown keys of h that travel in sync, in a stable
// form, local_ keys stay on their machine and are left out
func syncedExtra(h Host) string {
	keys := make([]string, 0, len(h.extra))
	for k := range h.extra {
		if !strings.HasPrefix(k, localPrefix) {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	var b bytes.Buffer
	for _, k := range keys {
		var v bytes.Buffer
		if json.Compact(&v, h.extra[k]) != nil {
			v.Reset()
			v.Write(h.extra[k])
		}
		b.WriteString(k)
		b.WriteByte(0)
		b.Write(v.Bytes())
		b.WriteByte(0)
	}
	return b.String()
}

// setAccess puts the access group and the travelling unknown keys of from
// into h, the local_ keys of h stay
func setAccess(h *Host, from Host) {
	h.Host, h.Port, h.User, h.Jump, h.Gateway = from.Host, from.Port, from.User, from.Jump, from.Gateway
	h.PasswordMode, h.Password, h.KeyMode, h.KeyPub = from.PasswordMode, from.Password, from.KeyMode, from.KeyPub
	extra := map[string]json.RawMessage{}
	for k, v := range h.extra {
		if strings.HasPrefix(k, localPrefix) {
			extra[k] = v
		}
	}
	for k, v := range from.extra {
		if !strings.HasPrefix(k, localPrefix) {
			extra[k] = v
		}
	}
	if len(extra) == 0 {
		extra = nil
	}
	h.extra = extra
}

// MergeThreeWay merges the changes local and remote made since base, the
// version both started from: a part only one side changed is taken from
// it, the same change on both sides once, ok is false when both changed the
// same part in different ways and the caller keeps both versions as a
// conflict copy, the access group is one part, the result starts from local
// so the fields of this device stay
func MergeThreeWay(base, local, remote Host) (merged Host, ok bool) {
	if base.format > hostFormat || local.format > hostFormat || remote.format > hostFormat {
		return local, false
	}
	merged = local
	// pick says whether remote's value is taken, ok is false on a conflict
	pick := func(b, l, r any) (useRemote, ok bool) {
		lc, rc := !reflect.DeepEqual(b, l), !reflect.DeepEqual(b, r)
		if lc && rc && !reflect.DeepEqual(l, r) {
			return false, false
		}
		return rc && !lc, true
	}

	useRemote, ok := pick(accessOf(base), accessOf(local), accessOf(remote))
	if !ok {
		return local, false
	}
	if useRemote {
		setAccess(&merged, remote)
	}
	if useRemote, ok = pick(base.Name, local.Name, remote.Name); !ok {
		return local, false
	} else if useRemote {
		merged.Name = remote.Name
	}
	if useRemote, ok = pick(base.Session, local.Session, remote.Session); !ok {
		return local, false
	} else if useRemote {
		merged.Session = remote.Session
	}
	merged.Tags = mergeTags(base.Tags, local.Tags, remote.Tags)
	if merged.Forwards, ok = mergeForwards(base.Forwards, local.Forwards, remote.Forwards); !ok {
		return local, false
	}
	return merged, true
}

// SameSynced tells whether a and b agree on every part MergeThreeWay
// merges, a merge result that equals the remote version has nothing new to
// push
func SameSynced(a, b Host) bool {
	return accessOf(a) == accessOf(b) && a.Name == b.Name && a.Session == b.Session &&
		slices.Equal(a.Tags, b.Tags) && slices.Equal(a.Forwards, b.Forwards)
}

// mergeTags is base without what either side removed plus what either
// added, sorted as tags are stored
func mergeTags(base, local, remote []string) []string {
	if slices.Equal(base, local) {
		return remote
	}
	if slices.Equal(base, remote) {
		return local
	}
	var out []string
	for _, t := range base {
		if slices.Contains(local, t) && slices.Contains(remote, t) {
			out = append(out, t)
		}
	}
	for _, list := range [][]string{local, remote} {
		for _, t := range list {
			if !slices.Contains(base, t) && !slices.Contains(out, t) {
				out = append(out, t)
			}
		}
	}
	slices.Sort(out)
	return out
}

// mergeForwards merges forwards by name, a forward both sides changed in
// different ways is a conflict, a side that left the list as it was takes
// the other's list as it is
func mergeForwards(base, local, remote []Forward) ([]Forward, bool) {
	switch {
	case slices.Equal(base, remote):
		return local, true
	case slices.Equal(base, local), slices.Equal(local, remote):
		return remote, true
	}
	byName := func(fs []Forward) map[string]Forward {
		m := make(map[string]Forward, len(fs))
		for _, f := range fs {
			m[f.Name] = f
		}
		return m
	}
	b, l, r := byName(base), byName(local), byName(remote)
	var names []string
	for _, m := range []map[string]Forward{b, l, r} {
		for n := range m {
			if !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
	}
	slices.Sort(names)
	var out []Forward
	for _, n := range names {
		bf, inB := b[n]
		lf, inL := l[n]
		rf, inR := r[n]
		lChanged := inL != inB || lf != bf
		rChanged := inR != inB || rf != bf
		switch {
		case lChanged && rChanged && (inL != inR || lf != rf):
			return nil, false
		case rChanged:
			if inR {
				out = append(out, rf)
			}
		case inL:
			out = append(out, lf)
		}
	}
	return out, true
}
