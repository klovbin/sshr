package app

import (
	"errors"
	"testing"
)

// with the list on, only an allowed host that still points where it did
// takes commands, the list survives a save (#101)
func TestCommandHosts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	store := &Store{Dir: t.TempDir()}
	h := &Host{ID: "0123456789abcdef0123456789abcdef", Name: "web", Host: "10.0.0.1", User: "u"}
	st, _ := LoadSettings()
	if st.CommandsAllowed(h.ID, h.Name, store.CommandTarget(h)) != nil {
		t.Fatal("the list is off, every host takes commands")
	}
	st.CommandsListedOnly = true
	if !errors.Is(st.CommandsAllowed(h.ID, h.Name, store.CommandTarget(h)), ErrCommandsNotAllowed) {
		t.Fatal("an unlisted host took commands")
	}
	st.AllowCommands(h.ID, store.CommandTarget(h))
	if err := SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	st, _ = LoadSettings()
	if err := st.CommandsAllowed(h.ID, h.Name, store.CommandTarget(h)); err != nil {
		t.Fatalf("an allowed host: %v", err)
	}
	moved := *h
	moved.Host = "evil.example"
	if !errors.Is(st.CommandsAllowed(moved.ID, moved.Name, store.CommandTarget(&moved)), ErrCommandsNotAllowed) {
		t.Fatal("a host that points elsewhere kept its permission")
	}
	st.DenyCommands(h.ID)
	if st.CommandsAllowed(h.ID, h.Name, store.CommandTarget(h)) == nil {
		t.Fatal("a denied host took commands")
	}
}

// a permission ends when a saved jump host of the host is repointed
// (#216)
func TestCommandTargetFollowsHops(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	store := &Store{Dir: t.TempDir()}
	bastion, err := store.Add(Host{Name: "bastion", Host: "10.0.0.9", User: "u"})
	if err != nil {
		t.Fatal(err)
	}
	web, err := store.Add(Host{Name: "web", Host: "10.0.0.1", User: "u", Jump: "bastion"})
	if err != nil {
		t.Fatal(err)
	}
	before := store.CommandTarget(web)
	moved := *bastion
	moved.Host = "evil.example"
	if _, err := store.Update(bastion.ID, moved); err != nil {
		t.Fatal(err)
	}
	if store.CommandTarget(web) == before {
		t.Fatal("the target did not change when the jump host was repointed")
	}
}
