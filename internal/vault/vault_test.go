package vault

import (
	"encoding/base64"
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

// mockKeychain is the system keychain of the front ends over the mock of
// go-keyring, MockInit and MockInitWithError decide what it answers
type mockKeychain struct{}

func (mockKeychain) Get(name string) (string, error) {
	v, err := keyring.Get("sshr", name)
	return v, mockNotFound(err)
}
func (mockKeychain) Set(name, value string) error { return keyring.Set("sshr", name, value) }
func (mockKeychain) Delete(name string) error     { return mockNotFound(keyring.Delete("sshr", name)) }

// State tells a locked keychain as the Secret Service says it, the full
// sorting of D-Bus errors is tested where the system keychain lives
func (mockKeychain) State(err error) error {
	if strings.Contains(err.Error(), "failed to unlock correct collection") {
		return ErrKeychainLocked
	}
	return nil
}

func mockNotFound(err error) error {
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrSecretNotFound
	}
	return err
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestSealBindsHostAndField(t *testing.T) {
	useMockKeychain(t)
	blob, err := Seal([]byte("pw"), "h1", "password")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Unseal(blob, "h1", "password"); err != nil || string(got) != "pw" {
		t.Fatalf("unseal = %q, %v", got, err)
	}
	if _, err := Unseal(blob, "h2", "password"); !errors.Is(err, ErrSealBroken) {
		t.Errorf("opened under another host: %v", err)
	}
	if _, err := Unseal(blob, "h1", "key"); !errors.Is(err, ErrSealBroken) {
		t.Errorf("opened as another field: %v", err)
	}
	// a fresh process reads the same key back from the keychain
	vaultKey = nil
	if got, err := Unseal(blob, "h1", "password"); err != nil || string(got) != "pw" {
		t.Errorf("after reload unseal = %q, %v", got, err)
	}
}

// mapKeychain is a Keychain in memory
type mapKeychain map[string]string

func (m mapKeychain) Get(name string) (string, error) {
	v, ok := m[name]
	if !ok {
		return "", ErrSecretNotFound
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
	key, err := Key()
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

// after storing a new vault key ran out of time no other key is made in
// this process (#173)
func TestNoSecondKeyAfterATimedOutStore(t *testing.T) {
	resetVault(t)
	old := keychain
	keychain = mapKeychain{}
	t.Cleanup(func() { keychain = old; keySetPending = false })
	keySetPending = true
	if _, err := Key(); err == nil || !errors.Is(err, ErrNoKeychain) {
		t.Fatalf("a key was made: %v", err)
	}
	if len(keychain.(mapKeychain)) != 0 {
		t.Fatal("a key reached the keychain")
	}
}

func resetVault(t *testing.T) {
	t.Helper()
	vaultMu.Lock()
	vaultKey = nil
	vaultMu.Unlock()
	keychain = mockKeychain{}
	dir := t.TempDir()
	vaultLockPath = func() (string, error) { return filepath.Join(dir, ".lock"), nil }
}

// a keychain that lost the vault key, or holds another one, is reported,
// a second key is not made over secrets sealed with the first (#145)
func TestVaultKeyLostIsNotReplaced(t *testing.T) {
	useMockKeychain(t)
	first, err := Key()
	if err != nil {
		t.Fatal(err)
	}
	vaultMu.Lock()
	vaultKey = nil
	vaultMu.Unlock()
	keyring.Delete(keyringService, keyringUser)
	if _, err := Key(); !errors.Is(err, ErrVaultKeyLost) {
		t.Fatalf("a lost key: %v", err)
	}
	if _, ok, _ := getVaultKey(); ok {
		t.Fatal("a second key was stored")
	}
	other := make([]byte, len(first))
	keyring.Set(keyringService, keyringUser, base64.StdEncoding.EncodeToString(other))
	if _, err := Key(); !errors.Is(err, ErrVaultKeyLost) {
		t.Fatalf("another key: %v", err)
	}
	keyring.Set(keyringService, keyringUser, base64.StdEncoding.EncodeToString(first))
	if got, err := Key(); err != nil || string(got) != string(first) {
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
	if _, err := Key(); err != nil {
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
	if _, err := Key(); err != nil {
		t.Fatalf("a folder that takes no write stopped the key: %v", err)
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
	_, err := Key()
	if !errors.Is(err, ErrKeychainTimeout) || !errors.Is(err, ErrNoKeychain) || time.Since(start) > time.Second {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
	if !strings.Contains(err.Error(), "did not answer") {
		t.Errorf("message %q", err)
	}
}

// a keychain call that answers after the time limit ends the quiet
// period, an unlock typed late does not keep the keychain refused (#173)
func TestLateKeychainAnswerEndsTheQuiet(t *testing.T) {
	old := keyringTimeout
	keyringTimeout = 50 * time.Millisecond
	t.Cleanup(func() {
		keyringTimeout = old
		keyringMu.Lock()
		keyringDownUntil = time.Time{}
		keyringMu.Unlock()
	})
	release, answered := make(chan struct{}), make(chan struct{})
	_, err := keyringCall(func() (string, error) {
		<-release
		defer close(answered)
		return "v", nil
	})
	if !errors.Is(err, errKeyringTimeout) {
		t.Fatalf("no timeout: %v", err)
	}
	if _, err := keyringCall(func() (string, error) { return "", nil }); !errors.Is(err, errKeyringTimeout) {
		t.Fatalf("the quiet period is off right after a timeout: %v", err)
	}
	close(release)
	<-answered
	time.Sleep(10 * time.Millisecond)
	if _, err := keyringCall(func() (string, error) { return "ok", nil }); err != nil {
		t.Fatalf("the late answer did not end the quiet period: %v", err)
	}
}
