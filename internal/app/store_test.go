package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddCleansFields(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Host: " 10.0.0.1 ", User: "u", Key: "/k", Password: "x", Jump: " a , b "})
	if err != nil {
		t.Fatal(err)
	}
	if h.Host != "10.0.0.1" || h.Name != "10.0.0.1" || h.Port != 22 {
		t.Errorf("defaults not applied: %+v", h)
	}
	if h.Password != "" {
		t.Errorf("password kept next to a key: %q", h.Password)
	}
	if h.Jump != "a,b" {
		t.Errorf("jump = %q, want a,b", h.Jump)
	}
	if h.ID == "" || h.CreatedAt.IsZero() {
		t.Errorf("ID or CreatedAt not set: %+v", h)
	}
}

func TestUpdateKeepsIDAndCreated(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Host: "10.0.0.1", User: "u"})
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.Update(h.ID, Host{Name: "n2", Host: "10.0.0.2", User: "u", Port: 2222})
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != h.ID || !u.CreatedAt.Equal(h.CreatedAt) {
		t.Errorf("ID or CreatedAt changed: %+v -> %+v", h, u)
	}
	got, err := s.Find(h.ID)
	if err != nil || got.Host != "10.0.0.2" || got.Port != 2222 || got.Name != "n2" {
		t.Errorf("saved host = %+v, %v", got, err)
	}
}

func TestAddRejects(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	cases := []struct {
		in   Host
		want error
	}{
		{Host{User: "u"}, ErrHostEmpty},
		{Host{Host: "h"}, ErrUserRequired},
		{Host{Host: "h", User: "u", Port: 70000}, ErrPortInvalid},
	}
	for _, c := range cases {
		if _, err := s.Add(c.in); !errors.Is(err, c.want) {
			t.Errorf("Add(%+v) = %v, want %v", c.in, err, c.want)
		}
	}
	if _, err := s.Add(Host{Name: "self", Host: "h", User: "u", Jump: "self"}); err == nil {
		t.Error("host jumping through itself was accepted")
	}
	if _, err := s.Update("nope", Host{Host: "h", User: "u"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("Update of a missing host = %v", err)
	}
}

func TestSavedPasswordTriedOnce(t *testing.T) {
	args := strings.Join(SSHArgs(&Host{Port: 22, PasswordMode: PasswordSaved}), " ")
	if !strings.Contains(args, "NumberOfPasswordPrompts=1") {
		t.Errorf("SSHArgs = %q, want NumberOfPasswordPrompts=1", args)
	}
	if strings.Contains(strings.Join(SSHArgs(&Host{Port: 22, Key: "/k"}), " "), "NumberOfPasswordPrompts") {
		t.Error("NumberOfPasswordPrompts set for a key host")
	}
}

func TestAskedPasswordRetries(t *testing.T) {
	args := strings.Join(SSHArgs(&Host{Port: 22, PasswordMode: PasswordAsk}), " ")
	if strings.Contains(args, "NumberOfPasswordPrompts") || !strings.Contains(args, "keyboard-interactive,password") {
		t.Errorf("SSHArgs = %q", args)
	}
}

func TestListAllNamesUnreadableFiles(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Host: "10.0.0.1", User: "u"})
	if err != nil {
		t.Fatal(err)
	}
	bad := strings.Repeat("a", 32)
	os.WriteFile(filepath.Join(s.Dir, bad+".json"), []byte("{"), 0o600)
	hosts, broken, err := s.ListAll()
	if err != nil || len(hosts) != 1 || hosts[0].ID != h.ID || len(broken) != 1 || broken[0] != bad {
		t.Fatalf("ListAll = %v %v %v", hosts, broken, err)
	}
}
