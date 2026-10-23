package app

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

// useMockKeychain swaps the system keychain for an in-memory one
func useMockKeychain(t *testing.T) {
	t.Helper()
	keyring.MockInit()
	resetVault(t)
}

func resetVault(t *testing.T) {
	t.Helper()
	vaultMu.Lock()
	vaultKey = nil
	vaultMu.Unlock()
	dir := t.TempDir()
	vaultLockPath = func() (string, error) { return filepath.Join(dir, ".lock"), nil }
}

// a keychain that lost the vault key, or holds another one, is reported,
// a second key is not made over secrets sealed with the first (#145)
func TestVaultKeyLostIsNotReplaced(t *testing.T) {
	useMockKeychain(t)
	first, err := VaultKey()
	if err != nil {
		t.Fatal(err)
	}
	vaultMu.Lock()
	vaultKey = nil
	vaultMu.Unlock()
	keyring.Delete(keyringService, keyringUser)
	if _, err := VaultKey(); !errors.Is(err, ErrVaultKeyLost) {
		t.Fatalf("a lost key: %v", err)
	}
	if _, ok, _ := getVaultKey(); ok {
		t.Fatal("a second key was stored")
	}
	other := make([]byte, len(first))
	keyring.Set(keyringService, keyringUser, base64.StdEncoding.EncodeToString(other))
	if _, err := VaultKey(); !errors.Is(err, ErrVaultKeyLost) {
		t.Fatalf("another key: %v", err)
	}
	keyring.Set(keyringService, keyringUser, base64.StdEncoding.EncodeToString(first))
	if got, err := VaultKey(); err != nil || string(got) != string(first) {
		t.Fatalf("the key brought back: %v", err)
	}
}

// a check that cannot be written does not keep an existing key from
// working
func TestVaultKeyCheckWriteIsBestEffort(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a read-only folder works differently on Windows")
	}
	useMockKeychain(t)
	if _, err := VaultKey(); err != nil {
		t.Fatal(err)
	}
	path, _ := keyCheckPath()
	os.Remove(path)
	dir := filepath.Dir(path)
	os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o700)
	vaultMu.Lock()
	vaultKey = nil
	vaultMu.Unlock()
	if _, err := VaultKey(); err != nil {
		t.Fatalf("a folder that takes no write stopped the key: %v", err)
	}
}

func TestSealBindsHostAndField(t *testing.T) {
	useMockKeychain(t)
	blob, err := seal([]byte("pw"), "h1", "password")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := unseal(blob, "h1", "password"); err != nil || string(got) != "pw" {
		t.Fatalf("unseal = %q, %v", got, err)
	}
	if _, err := unseal(blob, "h2", "password"); !errors.Is(err, ErrSealBroken) {
		t.Errorf("opened under another host: %v", err)
	}
	if _, err := unseal(blob, "h1", "key"); !errors.Is(err, ErrSealBroken) {
		t.Errorf("opened as another field: %v", err)
	}
	// a fresh process reads the same key back from the keychain
	vaultKey = nil
	if got, err := unseal(blob, "h1", "password"); err != nil || string(got) != "pw" {
		t.Errorf("after reload unseal = %q, %v", got, err)
	}
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
	old, err := seal([]byte("pw"), h.ID, "password")
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
	if !strings.HasPrefix(got.PasswordSealed, sealPrefix2) {
		t.Fatalf("not upgraded: %s", got.PasswordSealed)
	}
	if err := Unlock(got); err != nil || got.Password != "pw" {
		t.Fatalf("after the upgrade: %v %q", err, got.Password)
	}
}

// after a keychain call timed out the next ones fail at once instead of
// waiting the full timeout each, the error names the state (#169)
func TestKeychainQuietAfterATimeout(t *testing.T) {
	useMockKeychain(t)
	keyringMu.Lock()
	keyringDownUntil = time.Now().Add(time.Minute)
	keyringMu.Unlock()
	t.Cleanup(func() {
		keyringMu.Lock()
		keyringDownUntil = time.Time{}
		keyringMu.Unlock()
	})
	start := time.Now()
	_, err := VaultKey()
	if !errors.Is(err, ErrKeychainTimeout) || !errors.Is(err, ErrNoKeychain) || time.Since(start) > time.Second {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
	if !strings.Contains(err.Error(), "did not answer") {
		t.Errorf("message %q", err)
	}
}

// mapKeychain is a Keychain in memory
type mapKeychain map[string]string

func (m mapKeychain) Get(name string) (string, error) {
	v, ok := m[name]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}
func (m mapKeychain) Set(name, value string) error { m[name] = value; return nil }
func (m mapKeychain) Delete(name string) error     { delete(m, name); return nil }

// every secret of sshr goes through the Keychain, another implementation
// takes the vault key and the named secrets without the system keychain
func TestKeychainCanBeReplaced(t *testing.T) {
	resetVault(t)
	m := mapKeychain{}
	old := keychain
	keychain = m
	t.Cleanup(func() { keychain = old })
	key, err := VaultKey()
	if err != nil || len(key) != 32 || m["vault-key"] == "" {
		t.Fatalf("vault key %v, keychain %v", err, m)
	}
	if err := SecretSet("x", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := SecretGet("x"); err != nil || !ok || string(v) != "v" {
		t.Fatalf("%q %v %v", v, ok, err)
	}
	SecretDelete("x")
	if _, ok, _ := SecretGet("x"); ok {
		t.Error("the secret stayed")
	}
}
