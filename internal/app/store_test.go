package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestAddRefusesShellInHost(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	for _, h := range []Host{
		{Host: "a;b", User: "u"}, {Host: "a b", User: "u"}, {Host: "a\nb", User: "u"}, {Host: "$(id)", User: "u"},
	} {
		h.PasswordMode = PasswordAsk
		if _, err := s.Add(h); err == nil {
			t.Errorf("Add(%q, %q) was accepted", h.Host, h.User)
		}
	}
}

func TestImport(t *testing.T) {
	useMockKeychain(t)
	s := &Store{Dir: t.TempDir()}
	id := strings.Repeat("a", 32)
	if _, err := s.Import(Host{ID: "../x", Host: "10.0.0.1", User: "u"}); err == nil {
		t.Error("a bad id was imported")
	}
	if _, err := s.Import(Host{ID: id, Host: "10.0.0.1", User: "u", PasswordMode: PasswordSaved}); err == nil {
		t.Error("a saved-password host without its password was imported")
	}
	// a key kept in sshr stays only while it is the same key
	keyData, _ := testKey(t, "")
	h, err := s.Add(Host{Name: "v", Host: "10.0.0.1", User: "u", KeyData: keyData})
	if err != nil {
		t.Fatal(err)
	}
	same := *h
	got, err := s.Import(same)
	if err != nil || got.KeySealed == "" {
		t.Fatalf("same key: %v sealed=%q", err, got.KeySealed)
	}
	other := *h
	other.KeyPub = "ssh-ed25519 AAAAother"
	if got, err = s.Import(other); err != nil || got.KeySealed != "" {
		t.Fatalf("another key: %v sealed=%q", err, got.KeySealed)
	}
}

func TestAddChecksTheUser(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	for _, u := range []string{"u;id", "u u", "-oProxyCommand=x", "u\nx", "$(id)", "u`id`"} {
		if _, err := s.Add(Host{Host: "10.0.0.1", User: u, PasswordMode: PasswordAsk}); err == nil {
			t.Errorf("user %q was accepted", u)
		}
	}
	for _, u := range []string{"deploy", "first.last", "me@corp.example", `CORP\me`, "user-1", "_svc"} {
		if _, err := s.Add(Host{Host: "10.0.0.1", User: u, PasswordMode: PasswordAsk}); err != nil {
			t.Errorf("user %q was refused: %v", u, err)
		}
	}
}

func TestRecentHosts(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	var ids []string
	for _, n := range []string{"a", "b", "c"} {
		h, err := s.Add(Host{Name: n, Host: "10.0.0.1", User: "u", PasswordMode: PasswordAsk})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, h.ID)
	}
	if err := s.MarkConnected(ids[0]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	s.MarkConnected(ids[2])
	hosts, _ := s.List()
	SortRecent(hosts)
	if hosts[0].Name != "c" || hosts[1].Name != "a" || hosts[2].Name != "b" {
		t.Fatalf("order = %s %s %s", hosts[0].Name, hosts[1].Name, hosts[2].Name)
	}
	now := time.Now()
	for d, want := range map[time.Duration]string{10 * time.Second: "just now", 5 * time.Minute: "5 min ago", 3 * time.Hour: "3 h ago", 72 * time.Hour: "3 d ago"} {
		at := now.Add(-d)
		if got := Ago(&at, now); got != want {
			t.Errorf("Ago(%v) = %q, want %q", d, got, want)
		}
	}
	if Ago(nil, now) != "-" {
		t.Error("never connected")
	}
	// another device does not decide when this machine connected
	local, _ := s.Find(ids[0])
	in := *local
	in.LastConnected = nil
	out, _ := FromOtherDevice(in, local)
	if out.LastConnected == nil || !out.LastConnected.Equal(*local.LastConnected) {
		t.Error("the local last connect was not kept")
	}
}

func TestParseDestination(t *testing.T) {
	for in, want := range map[string]string{
		"deploy@10.0.0.7":            "deploy@10.0.0.7:22",
		"deploy@10.0.0.7:2222":       "deploy@10.0.0.7:2222",
		"ssh://deploy@db.example":    "deploy@db.example:22",
		"ssh://deploy@db.example:7/": "deploy@db.example:7",
		"u@[::1]:2200":               "u@::1:2200",
		"u@::1":                      "u@::1:22",
	} {
		h, err := ParseDestination(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got := fmt.Sprintf("%s@%s:%d", h.User, h.Host, h.Port); got != want {
			t.Errorf("%s = %s, want %s", in, got, want)
		}
		if h.ID != "" || h.PasswordMode != "" {
			t.Errorf("%s: %+v", in, h)
		}
	}
	for _, bad := range []string{"web", "10.0.0.7", "u:pw@host", "ssh://u:pw@host", "u@host:0", "u@host:99999", "u@a;b", "ssh://u@host/path", "-oProxyCommand=x@host"} {
		if _, err := ParseDestination(bad); err == nil {
			t.Errorf("%q was taken", bad)
		}
	}
}

func TestUpdateRefusesAnOlderCopy(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Host: "10.0.0.1", User: "u"})
	if err != nil {
		t.Fatal(err)
	}
	if h.Rev != 1 {
		t.Fatalf("Rev after Add = %d, want 1", h.Rev)
	}
	form := *h
	synced := *h
	synced.Port = 2299
	if _, err := s.Update(h.ID, synced); err != nil {
		t.Fatal(err)
	}
	form.Port = 2200
	if _, err := s.Update(h.ID, form); !errors.Is(err, ErrChanged) {
		t.Fatalf("Update from the older copy: err = %v, want ErrChanged", err)
	}
	cur, _ := s.Find(h.ID)
	if cur.Port != 2299 || cur.Rev != 2 {
		t.Fatalf("after the refused save port %d rev %d, want 2299 and 2", cur.Port, cur.Rev)
	}
	if err := s.MarkConnected(h.ID); err != nil {
		t.Fatal(err)
	}
	if cur, _ = s.Find(h.ID); cur.Rev != 2 {
		t.Errorf("MarkConnected changed Rev to %d, a connect must not refuse an open form", cur.Rev)
	}
	form.Rev = 0
	if u, err := s.Update(h.ID, form); err != nil || u.Port != 2200 || u.Rev != 3 {
		t.Fatalf("Update with Rev 0 = %+v, %v, want port 2200 rev 3", u, err)
	}
	in := *cur
	in.Rev = 0
	if u, err := s.Import(in); err != nil || u.Rev != 4 {
		t.Fatalf("Import = %+v, %v, want rev 4", u, err)
	}
}

func TestUpdateKeepsLastConnected(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Host: "10.0.0.1", User: "u"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkConnected(h.ID); err != nil {
		t.Fatal(err)
	}
	// the app builds the host from its form fields, LastConnected is nil
	u, err := s.Update(h.ID, Host{Host: "10.0.0.2", User: "u"})
	if err != nil {
		t.Fatal(err)
	}
	if u.LastConnected == nil {
		t.Fatal("an edit dropped the last connect time")
	}
}

// a key file and an agent stay on this machine while the destination
// does, a host that moved falls back to the default keys, a new host
// keeps what it brings (#195)
func TestFromOtherDeviceKeyFileAndAgent(t *testing.T) {
	local := &Host{Host: "10.0.0.5", User: "deploy", Port: 22, Key: "~/.ssh/mine"}
	out, _ := FromOtherDevice(Host{Host: "10.0.0.5", User: "deploy", Port: 22, Key: "~/.ssh/theirs"}, local)
	if out.Key != "~/.ssh/mine" {
		t.Errorf("the local key file was replaced: %q", out.Key)
	}
	out, notes := FromOtherDevice(Host{Host: "evil.example", User: "deploy", Port: 22, Key: "~/.ssh/work"}, local)
	if out.Key != "" || len(notes) == 0 {
		t.Errorf("a moved host kept a key file: %q %v", out.Key, notes)
	}
	agentLocal := &Host{Host: "10.0.0.5", User: "deploy", Port: 22, KeyMode: KeyAgent, Agent: "/run/mine.sock", KeyPub: "ssh-ed25519 AAA"}
	out, _ = FromOtherDevice(Host{Host: "10.0.0.5", User: "deploy", Port: 22, KeyMode: KeyAgent, Agent: "/tmp/theirs.sock"}, agentLocal)
	if out.Agent != "/run/mine.sock" {
		t.Errorf("the local agent was replaced: %q", out.Agent)
	}
	out, _ = FromOtherDevice(Host{Host: "evil.example", User: "deploy", Port: 22, KeyMode: KeyAgent, Agent: "/tmp/theirs.sock", KeyPub: "ssh-ed25519 BBB"}, agentLocal)
	if out.Agent != "" || out.KeyMode != "" || out.KeyPub != "" {
		t.Errorf("a moved host kept its agent: %+v", out)
	}
	// a host on the default keys here does not take a key file or an agent
	// from another device (#199)
	plain := &Host{Host: "10.0.0.5", User: "deploy", Port: 22}
	out, _ = FromOtherDevice(Host{Host: "10.0.0.5", User: "deploy", Port: 22, Key: "~/.ssh/id_work"}, plain)
	if out.Key != "" {
		t.Errorf("a key file came from another device: %q", out.Key)
	}
	out, notes = FromOtherDevice(Host{Host: "10.0.0.5", User: "deploy", Port: 22, KeyMode: KeyAgent, Agent: "/tmp/evil.sock", KeyPub: "ssh-ed25519 CCC"}, plain)
	if out.KeyMode != "" || out.Agent != "" || out.KeyPub != "" || len(notes) == 0 {
		t.Errorf("an agent came from another device: %+v %v", out, notes)
	}
	out, _ = FromOtherDevice(Host{Host: "10.0.0.5", User: "deploy", Port: 22, KeyMode: KeyAgent, Agent: "/run/mine.sock", KeyPub: "ssh-ed25519 CCC"}, agentLocal)
	if out.KeyPub != "ssh-ed25519 AAA" {
		t.Errorf("the agent key came from another device: %q", out.KeyPub)
	}
	out, _ = FromOtherDevice(Host{Host: "10.0.0.9", User: "deploy", Port: 22, Key: "~/.ssh/id_ed25519"}, nil)
	if out.Key != "~/.ssh/id_ed25519" {
		t.Errorf("a new host lost its key file: %q", out.Key)
	}
}
