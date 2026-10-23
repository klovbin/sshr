package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"sshr.dev/internal/vault"
)

// useMockKeychain swaps the system keychain for the in-memory mock of
// go-keyring and starts from a clean vault
func useMockKeychain(t *testing.T) {
	t.Helper()
	keyring.MockInit()
	resetVault(t)
}

// resetVault starts from a clean vault with its files in a folder of the
// test, the system keychain of app stays in place
func resetVault(t *testing.T) {
	t.Helper()
	vault.SetKeychain(systemKeychain{})
	vault.ResetForTest(filepath.Join(t.TempDir(), ".lock"))
}

func TestSavedPasswordIsSealed(t *testing.T) {
	useMockKeychain(t)
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Host: "h", User: "u", PasswordMode: PasswordSaved, Password: " secret "})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(s.Dir, h.ID+".json"))
	if strings.Contains(string(b), "secret") || !strings.Contains(string(b), `"password_sealed": "v2:`) {
		t.Fatalf("host file:\n%s", b)
	}
	got, _ := s.Find(h.ID)
	if got.Password != "" {
		t.Error("Find decrypted the password")
	}
	if err := Unlock(got); err != nil || got.Password != " secret " {
		t.Errorf("Unlock = %q, %v", got.Password, err)
	}
	// editing other fields without typing the password keeps it
	in := Host{Name: "n2", Host: "h", User: "u", PasswordMode: PasswordSaved}
	if _, err := s.Update(h.ID, in); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Find(h.ID)
	if err := Unlock(got); err != nil || got.Password != " secret " {
		t.Errorf("after edit Unlock = %q, %v", got.Password, err)
	}
	if _, err := s.Add(Host{Host: "h", User: "u", PasswordMode: PasswordSaved}); !errors.Is(err, ErrPasswordRequired) {
		t.Errorf("saved mode with no password: %v", err)
	}
}

func TestPlainPasswordMigrates(t *testing.T) {
	useMockKeychain(t)
	s := &Store{Dir: t.TempDir()}
	old := `{"id":"abc","name":"old","host":"h","port":22,"user":"u","password":"pw1"}`
	os.WriteFile(filepath.Join(s.Dir, "abc.json"), []byte(old), 0o600)
	h, err := s.Find("old")
	if err != nil || h.PasswordMode != PasswordSaved {
		t.Fatalf("old host = %+v, %v", h, err)
	}
	if err := Unlock(h); err != nil || h.Password != "pw1" {
		t.Fatalf("Unlock old = %q, %v", h.Password, err)
	}
	h.Password = ""
	if _, err := s.Update(h.ID, *h); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(s.Dir, "abc.json"))
	if strings.Contains(string(b), "pw1") || !strings.Contains(string(b), "password_sealed") {
		t.Errorf("not migrated:\n%s", b)
	}
}

func TestNoKeychain(t *testing.T) {
	keyring.MockInitWithError(errors.New("no bus"))
	resetVault(t)
	t.Cleanup(keyring.MockInit)
	s := &Store{Dir: t.TempDir()}
	if _, err := s.Add(Host{Host: "h", User: "u", PasswordMode: PasswordSaved, Password: "x"}); !errors.Is(err, ErrNoKeychain) {
		t.Errorf("saved without a keychain: %v", err)
	}
	if _, err := s.Add(Host{Host: "h", User: "u", PasswordMode: PasswordAsk}); err != nil {
		t.Errorf("ask mode needs no keychain: %v", err)
	}
	// an old plain password keeps working and stays until the keychain is back
	old := `{"id":"abc","name":"old","host":"h","port":22,"user":"u","password":"pw1"}`
	os.WriteFile(filepath.Join(s.Dir, "abc.json"), []byte(old), 0o600)
	h, _ := s.Find("old")
	if _, err := s.Update(h.ID, *h); err != nil {
		t.Fatalf("edit of an old host without a keychain: %v", err)
	}
	h, _ = s.Find("old")
	if err := Unlock(h); err != nil || h.Password != "pw1" {
		t.Errorf("old password lost: %q, %v", h.Password, err)
	}
}

func TestSavedPasswordBoundToDestination(t *testing.T) {
	useMockKeychain(t)
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Name: "w", Host: "10.0.0.1", User: "u", PasswordMode: PasswordSaved, Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	// an address changed in the file outside sshr does not open it
	path := filepath.Join(s.Dir, h.ID+".json")
	b, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(b), `"10.0.0.1"`, `"203.0.113.66"`, 1)), 0o600)
	moved, _ := s.Find(h.ID)
	if err := Unlock(moved); err == nil {
		t.Fatal("the password opened for an address changed outside sshr")
	}
	os.WriteFile(path, b, 0o600)
	// an address changed through sshr keeps the password
	cur, _ := s.Find(h.ID)
	cur.Host, cur.Port = "10.0.0.2", 2222
	if _, err := s.Update(h.ID, *cur); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Find(h.ID)
	if err := Unlock(got); err != nil || got.Password != "pw" {
		t.Fatalf("after an edit in sshr: %v %q", err, got.Password)
	}
}

func TestOlderSealsAreUpgraded(t *testing.T) {
	useMockKeychain(t)
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Name: "w", Host: "10.0.0.1", User: "u", PasswordMode: PasswordSaved, Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	old, err := vault.Seal([]byte("pw"), h.ID, "password")
	if err != nil {
		t.Fatal(err)
	}
	h.Password, h.PasswordSealed = "", old
	b, _ := json.MarshalIndent(h, "", "  ")
	os.WriteFile(filepath.Join(s.Dir, h.ID+".json"), b, 0o600)
	v1, _ := s.Find(h.ID)
	if err := Unlock(v1); err != nil || v1.Password != "pw" {
		t.Fatalf("a v1 password does not open: %v", err)
	}
	s.upgradeSeals()
	got, _ := s.Find(h.ID)
	if !strings.HasPrefix(got.PasswordSealed, vault.SealPrefix2) {
		t.Fatalf("not upgraded: %s", got.PasswordSealed)
	}
	if err := Unlock(got); err != nil || got.Password != "pw" {
		t.Fatalf("after the upgrade: %v %q", err, got.Password)
	}
}

// a password an old version wrote in clear is sealed at the next start
// once the keychain works (#176)
func TestClearPasswordIsSealedAtStart(t *testing.T) {
	useMockKeychain(t)
	s := &Store{Dir: t.TempDir()}
	id := "0123456789abcdef0123456789abcdef"
	path := filepath.Join(s.Dir, id+".json")
	os.WriteFile(path, []byte(`{"id":"`+id+`","name":"w","host":"10.0.0.1","port":22,"user":"u","password":"pw","created_at":"2026-10-01T00:00:00Z"}`), 0o600)
	s.upgradeSeals()
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), `"password"`) || !strings.Contains(string(b), `"password_sealed": "v2:`) {
		t.Fatalf("host file:\n%s", b)
	}
	h, _ := s.Find(id)
	if err := Unlock(h); err != nil || h.Password != "pw" {
		t.Fatalf("%v %q", err, h.Password)
	}
}

// with no keychain the start upgrade does not rewrite a clear-password
// host (#178)
func TestClearPasswordLeftAloneWithoutKeychain(t *testing.T) {
	keyring.MockInitWithError(errors.New("no bus"))
	resetVault(t)
	t.Cleanup(keyring.MockInit)
	s := &Store{Dir: t.TempDir()}
	id := "0123456789abcdef0123456789abcdef"
	path := filepath.Join(s.Dir, id+".json")
	raw := `{"id":"` + id + `","name":"w","host":"10.0.0.1","port":22,"user":"u","password":"pw","created_at":"2026-10-01T00:00:00Z"}`
	os.WriteFile(path, []byte(raw), 0o600)
	before, _ := os.Stat(path)
	time.Sleep(10 * time.Millisecond)
	s.upgradeSeals()
	after, _ := os.Stat(path)
	if b, _ := os.ReadFile(path); string(b) != raw || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("the host was written:\n%s", b)
	}
}

// with no terminal of its own (mcp) the passphrase comes only from
// SSHR_ASKPASS, never from a prompt
func TestPassphraseWithoutTerminal(t *testing.T) {
	t.Setenv("SSHR_ASKPASS", "")
	NoTerminalPrompts = true
	t.Cleanup(func() { NoTerminalPrompts = false })
	if _, err := promptPassphrase("x"); !errors.Is(err, ErrNoPassphrase) {
		t.Fatalf("%v", err)
	}
}
