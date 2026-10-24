//go:build !windows

package app

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sshr.dev/internal/pwmgr"
)

// fakeOP puts a shell script in place of op, read answers from files named
// after the reference, item create keeps the template it got on stdin
func fakeOP(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
[ -n "$FAKEOP_FAIL" ] && { echo '[ERROR] 2026/10/17 12:00:00 account is not signed in' >&2; exit 1; }
case "$1" in
read) f="$FAKEOP_DIR/$(printf '%s' "$3" | tr '/?: =' '_____')"; [ -f "$f" ] || { echo "[ERROR] item not found" >&2; exit 1; }; cat "$f" ;;
item) echo "$*" > "$FAKEOP_DIR/create.args"; cat > "$FAKEOP_DIR/create.json"
  echo '{"id":"it1","vault":{"id":"v1"},"fields":[{"purpose":"USERNAME","reference":"op://v1/it1/username"},{"purpose":"PASSWORD","reference":"op://v1/it1/password"}]}' ;;
esac
`
	bin := filepath.Join(dir, "op")
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	old := pwmgr.OPBin
	pwmgr.OPBin = bin
	t.Cleanup(func() { pwmgr.OPBin = old })
	t.Setenv("FAKEOP_DIR", dir)
	return dir
}

func opFile(dir, ref, value string) {
	name := strings.NewReplacer("/", "_", "?", "_", ":", "_", " ", "_", "=", "_").Replace(ref)
	os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600)
}

func TestOnePasswordLinkedPassword(t *testing.T) {
	dir := fakeOP(t)
	opFile(dir, "op://Private/web/password", "pw 1")
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Host: "h", User: "u", PasswordMode: PasswordOnePassword, PasswordRef: "op://Private/web/password"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(s.Dir, h.ID+".json"))
	if strings.Contains(string(b), "pw 1") || strings.Contains(string(b), "sealed") {
		t.Errorf("host file:\n%s", b)
	}
	got, _ := s.Find(h.ID)
	if err := Unlock(got); err != nil || got.Password != "pw 1" {
		t.Errorf("Unlock = %q, %v", got.Password, err)
	}
	if !strings.Contains(strings.Join(SSHArgs(got), " "), "NumberOfPasswordPrompts=1") {
		t.Error("a 1Password password is retried")
	}
	if _, err := s.Add(Host{Host: "h", User: "u", PasswordMode: PasswordOnePassword, PasswordRef: "Private/web"}); err == nil {
		t.Error("a reference without op:// accepted")
	}
}

func TestOnePasswordCreatesItem(t *testing.T) {
	dir := fakeOP(t)
	vault := "Servers"
	s := &Store{Dir: t.TempDir(), OPVault: &vault}
	h, err := s.Add(Host{Name: "web", Host: "h", User: "deploy", PasswordMode: PasswordOnePassword, Password: "new pw"})
	if err != nil {
		t.Fatal(err)
	}
	if h.PasswordRef != "op://v1/it1/password" || h.Password != "" {
		t.Errorf("host = %+v", h)
	}
	args, _ := os.ReadFile(filepath.Join(dir, "create.args"))
	if strings.Contains(string(args), "new pw") || !strings.Contains(string(args), "--vault Servers") {
		t.Errorf("op args: %s", args)
	}
	tmpl, _ := os.ReadFile(filepath.Join(dir, "create.json"))
	if !strings.Contains(string(tmpl), `"value":"new pw"`) || !strings.Contains(string(tmpl), `"value":"deploy"`) {
		t.Errorf("template: %s", tmpl)
	}
	b, _ := os.ReadFile(filepath.Join(s.Dir, h.ID+".json"))
	if strings.Contains(string(b), "new pw") {
		t.Errorf("password in the host file:\n%s", b)
	}
	// a new password for a linked host is changed in 1Password, not here
	if _, err := s.Update(h.ID, Host{Name: "web", Host: "h", User: "deploy", PasswordMode: PasswordOnePassword, Password: "x"}); err == nil {
		t.Error("password of a linked host replaced")
	}
	if _, err := s.Update(h.ID, Host{Name: "web2", Host: "h", User: "deploy", PasswordMode: PasswordOnePassword}); err != nil {
		t.Errorf("edit keeping the item: %v", err)
	}
}

func TestOnePasswordKey(t *testing.T) {
	dir := fakeOP(t)
	data, pub := testKey(t, "")
	opFile(dir, "op://Private/ssh/private key?ssh-format=openssh", string(data))
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Host: "h", User: "u", KeyMode: KeyOnePassword, KeyRef: "op://Private/ssh/private key"})
	if err != nil {
		t.Fatal(err)
	}
	if h.KeyPub != pub || h.KeySealed != "" {
		t.Fatalf("host = %+v", h)
	}
	b, _ := os.ReadFile(filepath.Join(s.Dir, h.ID+".json"))
	if strings.Contains(string(b), "PRIVATE KEY") {
		t.Errorf("private key in the host file:\n%s", b)
	}
	got, _ := s.Find(h.ID)
	cmd := exec.Command("true")
	stop, err := AttachAuth(cmd, got)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if args, err := s.ConnectArgs(got); err != nil || !strings.Contains(strings.Join(args, " "), "IdentitiesOnly=yes") {
		t.Error("no agent options for a 1Password key")
	}
}

func TestOnePasswordLocked(t *testing.T) {
	fakeOP(t)
	t.Setenv("FAKEOP_FAIL", "1")
	h := &Host{Name: "web", PasswordMode: PasswordOnePassword, PasswordRef: "op://a/b/password"}
	err := Unlock(h)
	if err == nil || !strings.Contains(err.Error(), "not signed in") {
		t.Errorf("Unlock locked = %v", err)
	}
	old := pwmgr.OPBin
	pwmgr.OPBin = "sshr-no-such-op"
	defer func() { pwmgr.OPBin = old }()
	if err := Unlock(h); !errors.Is(err, ErrNoOP) {
		t.Errorf("no op: %v", err)
	}
}
