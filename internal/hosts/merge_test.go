package hosts

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"
)

// TestMergeGroupsCoverHost fails when a field of Host is in no group of
// MergeThreeWay or in two, a new field must be placed on purpose
func TestMergeGroupsCoverHost(t *testing.T) {
	seen := map[string]int{}
	for _, g := range [][]string{mergeAccess, mergeField, mergeSet, mergeKept} {
		for _, f := range g {
			seen[f]++
		}
	}
	typ := reflect.TypeOf(Host{})
	for i := range typ.NumField() {
		name := typ.Field(i).Name
		if seen[name] != 1 {
			t.Errorf("field %s is in %d merge groups, put it in exactly one in merge.go", name, seen[name])
		}
		delete(seen, name)
	}
	for f := range seen {
		t.Errorf("merge group names %s, Host has no such field", f)
	}
}

func mergeBase() Host {
	return Host{ID: "a", Name: "web", Host: "10.0.0.1", Port: 22, User: "root",
		PasswordMode: PasswordSaved, Password: "old", Tags: []string{"prod"},
		Forwards: []Forward{{Name: "db", Kind: "L", Spec: "5432:localhost:5432"}}}
}

func TestMergeThreeWay(t *testing.T) {
	type edit func(*Host)
	cases := []struct {
		name          string
		local, remote edit
		ok            bool
		want          edit
	}{
		{"rename here, tag there", func(h *Host) { h.Name = "web1" }, func(h *Host) { h.Tags = []string{"eu", "prod"} },
			true, func(h *Host) { h.Name, h.Tags = "web1", []string{"eu", "prod"} }},
		{"same rename on both", func(h *Host) { h.Name = "w" }, func(h *Host) { h.Name = "w" },
			true, func(h *Host) { h.Name = "w" }},
		{"two renames", func(h *Host) { h.Name = "a" }, func(h *Host) { h.Name = "b" }, false, nil},
		{"password here, address there", func(h *Host) { h.Password = "new" }, func(h *Host) { h.Host = "10.0.0.2" }, false, nil},
		{"address there, session here", func(h *Host) { h.Session = "tmux" }, func(h *Host) { h.Host, h.Password = "10.0.0.2", "other" },
			true, func(h *Host) { h.Session, h.Host, h.Password = "tmux", "10.0.0.2", "other" }},
		{"tag added on each side, one removed", func(h *Host) { h.Tags = []string{"a"} }, func(h *Host) { h.Tags = []string{"b", "prod"} },
			true, func(h *Host) { h.Tags = []string{"a", "b"} }},
		{"forward added on each side", func(h *Host) {
			h.Forwards = append(slices.Clone(h.Forwards), Forward{Name: "web", Kind: "L", Spec: "8080:localhost:80"})
		},
			func(h *Host) {
				h.Forwards = append(slices.Clone(h.Forwards), Forward{Name: "socks", Kind: "D", Spec: "1080"})
			},
			true, func(h *Host) {
				h.Forwards = []Forward{h.Forwards[0], {Name: "socks", Kind: "D", Spec: "1080"}, {Name: "web", Kind: "L", Spec: "8080:localhost:80"}}
			}},
		{"same forward changed two ways", func(h *Host) { h.Forwards = []Forward{{Name: "db", Kind: "L", Spec: "1:localhost:1"}} },
			func(h *Host) { h.Forwards = []Forward{{Name: "db", Kind: "L", Spec: "2:localhost:2"}} }, false, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			local, remote := mergeBase(), mergeBase()
			c.local(&local)
			c.remote(&remote)
			got, ok := MergeThreeWay(mergeBase(), local, remote)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if !ok {
				return
			}
			want := mergeBase()
			c.want(&want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("merged\n%+v\nwant\n%+v", got, want)
			}
		})
	}
}

// TestMergeKeepsDeviceFields checks that the key file, the agent and the
// local_ keys of this device stay while the access group comes from the
// other side
func TestMergeKeepsDeviceFields(t *testing.T) {
	base := mergeBase()
	local := mergeBase()
	local.Key, local.Agent, local.Name = "~/.ssh/id_here", "1password", "here"
	local.extra = map[string]json.RawMessage{"local_x": json.RawMessage(`1`)}
	remote := mergeBase()
	remote.Key, remote.Host = "~/.ssh/id_there", "10.0.0.9"
	remote.extra = map[string]json.RawMessage{"future": json.RawMessage(`"v"`)}
	got, ok := MergeThreeWay(base, local, remote)
	if !ok {
		t.Fatal("conflict")
	}
	if got.Key != "~/.ssh/id_here" || got.Agent != "1password" || got.Host != "10.0.0.9" || got.Name != "here" {
		t.Fatalf("got %+v", got)
	}
	if string(got.extra["local_x"]) != "1" || string(got.extra["future"]) != `"v"` {
		t.Fatalf("extra %v", got.extra)
	}
}

func TestMergeNewerFormat(t *testing.T) {
	remote := mergeBase()
	remote.format = hostFormat + 1
	if _, ok := MergeThreeWay(mergeBase(), mergeBase(), remote); ok {
		t.Fatal("a host of a newer format merged")
	}
}

func TestSameSynced(t *testing.T) {
	a, b := mergeBase(), mergeBase()
	b.Key, b.Rev = "other", 7
	if !SameSynced(a, b) {
		t.Fatal("device fields counted")
	}
	b.Password = "x"
	if SameSynced(a, b) {
		t.Fatal("password not counted")
	}
}
