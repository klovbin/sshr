//go:build !windows

package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshr.dev/internal/pwmgr"
)

// fakeBW puts a shell script in place of bw, answers come from files named
// after the command and item, it records its arguments
func fakeBW(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
echo "$*" >> "$FAKEBW_DIR/args"
[ -n "$FAKEBW_LOCKED" ] && { echo 'Vault is locked.' >&2; exit 1; }
f="$FAKEBW_DIR/$2-$3"
[ -f "$f" ] || { echo 'Not found.' >&2; exit 1; }
cat "$f"
`
	bin := filepath.Join(dir, "bw")
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	old := pwmgr.BWBin
	pwmgr.BWBin = bin
	t.Cleanup(func() { pwmgr.BWBin = old })
	t.Setenv("FAKEBW_DIR", dir)
	return dir
}

func TestBitwardenPassword(t *testing.T) {
	dir := fakeBW(t)
	os.WriteFile(filepath.Join(dir, "password-web1"), []byte("pw bw\n"), 0o600)
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Host: "h", User: "u", PasswordMode: PasswordBitwarden, PasswordRef: "web1", Password: "ignored"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(s.Dir, h.ID+".json"))
	if strings.Contains(string(b), "pw bw") || strings.Contains(string(b), "ignored") {
		t.Errorf("host file:\n%s", b)
	}
	got, _ := s.Find(h.ID)
	if err := Unlock(got); err != nil || got.Password != "pw bw" {
		t.Fatalf("Unlock = %q, %v", got.Password, err)
	}
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	if !strings.Contains(string(args), "get password web1 --nointeraction") {
		t.Errorf("bw args: %s", args)
	}
	if !got.PasswordFromSshr() || !strings.Contains(strings.Join(SSHArgs(got), " "), "NumberOfPasswordPrompts=1") {
		t.Error("a Bitwarden password is not handed to ssh once")
	}
	t.Setenv("FAKEBW_LOCKED", "1")
	got.Password = ""
	if err := Unlock(got); err == nil || !strings.Contains(err.Error(), "BW_SESSION") {
		t.Errorf("locked vault error = %v", err)
	}
	for _, bad := range []string{"", "--session=x", "a\nb"} {
		if _, err := s.Add(Host{Host: "h", User: "u", PasswordMode: PasswordBitwarden, PasswordRef: bad}); err == nil {
			t.Errorf("reference %q accepted", bad)
		}
	}
}

func TestBitwardenKey(t *testing.T) {
	useMockKeychain(t)
	dir := fakeBW(t)
	priv, pub := testKey(t, "")
	item, _ := json.Marshal(map[string]any{"name": "web key", "sshKey": map[string]string{"privateKey": string(priv), "publicKey": pub}})
	os.WriteFile(filepath.Join(dir, "item-k1"), item, 0o600)
	os.WriteFile(filepath.Join(dir, "item-login"), []byte(`{"name":"a login","login":{}}`), 0o600)
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Host: "h", User: "u", KeyMode: KeyBitwarden, KeyRef: "k1"})
	if err != nil {
		t.Fatal(err)
	}
	if h.KeyPub != pub || !h.ServedByAgent() {
		t.Fatalf("KeyPub = %q, want %q", h.KeyPub, pub)
	}
	raw, err := loadKey(h)
	if err != nil || raw == nil {
		t.Fatalf("loadKey = %v", err)
	}
	if _, err := s.Add(Host{Host: "h", User: "u", KeyMode: KeyBitwarden, KeyRef: "login"}); err == nil || !strings.Contains(err.Error(), "not an SSH Key item") {
		t.Errorf("login item as key: %v", err)
	}
}

func TestBitwardenRefsStayLocal(t *testing.T) {
	in := Host{Name: "x", PasswordMode: PasswordBitwarden, PasswordRef: "bank", KeyMode: KeyBitwarden, KeyRef: "key"}
	out, notes := FromOtherDevice(in, nil)
	if out.PasswordRef != "" || out.KeyRef != "" || out.KeyMode != "" || out.PasswordMode != PasswordAsk || len(notes) != 2 {
		t.Fatalf("out = %+v notes %v", out, notes)
	}
	local := &Host{PasswordMode: PasswordBitwarden, PasswordRef: "mine"}
	if out, _ = FromOtherDevice(Host{PasswordMode: PasswordBitwarden, PasswordRef: "theirs"}, local); out.PasswordRef != "mine" {
		t.Fatalf("local reference lost: %+v", out)
	}
}

// a stolen device must not send this machine's secret to a new address (#42)
func TestManagerRefDroppedWhenDestinationChanges(t *testing.T) {
	local := &Host{Host: "10.0.0.5", User: "deploy", Port: 22, PasswordMode: PasswordBitwarden, PasswordRef: "mine"}
	for _, in := range []Host{
		{Host: "attacker.example", User: "deploy", Port: 22, PasswordMode: PasswordBitwarden},
		{Host: "10.0.0.5", User: "root", Port: 22, PasswordMode: PasswordBitwarden},
		{Host: "10.0.0.5", User: "deploy", Port: 2222, PasswordMode: PasswordBitwarden},
		{Host: "10.0.0.5", User: "deploy", Port: 22, Jump: "evil", PasswordMode: PasswordBitwarden},
	} {
		out, notes := FromOtherDevice(in, local)
		if out.PasswordRef != "" || out.PasswordMode != PasswordAsk || len(notes) == 0 {
			t.Errorf("%+v kept the reference: %+v", in, out)
		}
	}
	out, _ := FromOtherDevice(Host{Host: "10.0.0.5", User: "deploy", PasswordMode: PasswordBitwarden, Tags: []string{"new"}}, local)
	if out.PasswordRef != "mine" {
		t.Errorf("an edit that keeps the destination lost the reference: %+v", out)
	}
}

func TestDuplicateDoesNotReadManagerSecret(t *testing.T) {
	dir := fakeBW(t)
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Host: "h", User: "u", PasswordMode: PasswordBitwarden, PasswordRef: "web1"})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := s.Duplicate(h.ID, "h copy")
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "args")); err == nil {
		t.Fatalf("Duplicate ran bw: %s", b)
	}
	if cp.PasswordMode != PasswordBitwarden || cp.PasswordRef != "web1" || cp.Password != "" {
		t.Fatalf("copy = %+v", cp)
	}
}
