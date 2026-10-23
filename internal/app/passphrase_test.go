package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

// cheapPassphrase makes Argon2 fast and answers the prompt with pass
func cheapPassphrase(t *testing.T, pass *string) {
	t.Helper()
	old, oldAsk := argonParams, askPassphrase
	argonParams.Time, argonParams.MemoryKiB, argonParams.Threads = 1, 8, 1
	askPassphrase = func(string) (string, error) { return *pass, nil }
	t.Cleanup(func() { argonParams, askPassphrase = old, oldAsk })
}

func forgetVaultKey() {
	vaultMu.Lock()
	vaultKey = nil
	vaultMu.Unlock()
}

// the vault key moves into a file under a passphrase and stays the same
// key, so what was sealed before still opens on a machine without a
// keychain, a wrong passphrase opens nothing (#98)
func TestPassphraseVault(t *testing.T) {
	useMockKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	pass := "correct horse battery"
	cheapPassphrase(t, &pass)
	key, err := VaultKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := SetVaultPassphrase("short pass"); err == nil {
		t.Error("a short passphrase was taken")
	}
	if err := SetVaultPassphrase(pass); err != nil {
		t.Fatal(err)
	}
	if VaultMode() != VaultPassphrase {
		t.Fatalf("mode %s", VaultMode())
	}
	// a machine without a keychain
	keyring.MockInitWithError(errors.New("no bus"))
	t.Cleanup(keyring.MockInit)
	forgetVaultKey()
	got, err := VaultKey()
	if err != nil || string(got) != string(key) {
		t.Fatalf("the file did not give the same key: %v", err)
	}
	forgetVaultKey()
	pass = "wrong"
	if _, err := VaultKey(); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("a wrong passphrase: %v", err)
	}
	if _, ok, _ := getVaultKey(); ok {
		t.Error("a key was made")
	}
	// back to the keychain
	keyring.MockInit()
	pass = "correct horse battery"
	forgetVaultKey()
	if err := UseKeychainVault(); err != nil {
		t.Fatal(err)
	}
	if VaultMode() != VaultKeychain {
		t.Errorf("mode %s", VaultMode())
	}
	if k, ok, _ := getVaultKey(); !ok || string(k) != string(key) {
		t.Error("the keychain does not hold the key")
	}
	if path, _ := passphraseFilePath(); fileExists(path) {
		t.Error("the vault key file stayed")
	}
}

// a crafted vault key file cannot make sshr spend gigabytes on Argon2
func TestPassphraseFileLimits(t *testing.T) {
	w := &wrappedKey{Version: 1, KDF: "argon2id", Time: 1, MemoryKiB: 64 * 1024 * 1024, Threads: 1, Salt: make([]byte, 16), Sealed: make([]byte, 64)}
	if _, err := unwrapKey(w, "x"); err == nil {
		t.Fatal("a file asking for 64 GiB was used")
	}
	b, _ := json.Marshal(w)
	if len(b) == 0 {
		t.Fatal("marshal")
	}
}

// with no terminal of its own (mcp) the passphrase comes only from
// SSHR_ASKPASS, never from a prompt
func TestPassphraseWithoutTerminal(t *testing.T) {
	t.Setenv("SSHR_ASKPASS", "")
	NoTerminalPrompts = true
	t.Cleanup(func() { NoTerminalPrompts = false })
	if _, err := askPassphrase("x"); !errors.Is(err, ErrNoPassphrase) {
		t.Fatalf("%v", err)
	}
}

// under the passphrase vault the named secrets (the sync device keys) live
// sealed in a file, a machine without a keychain keeps them (#98)
func TestNamedSecretsInPassphraseMode(t *testing.T) {
	useMockKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	pass := "correct horse battery"
	cheapPassphrase(t, &pass)
	if err := SecretSet("sync-device", []byte("seed")); err != nil {
		t.Fatal(err)
	}
	if err := SetVaultPassphrase(pass); err != nil {
		t.Fatal(err)
	}
	if err := MoveSecrets([]string{"sync-device", "sync-key-1"}, true); err != nil {
		t.Fatal(err)
	}
	keyring.MockInitWithError(errors.New("no bus"))
	t.Cleanup(keyring.MockInit)
	forgetVaultKey()
	v, ok, err := SecretGet("sync-device")
	if err != nil || !ok || string(v) != "seed" {
		t.Fatalf("%q %v %v", v, ok, err)
	}
	if err := SecretSet("sync-key-2", []byte("k2")); err != nil {
		t.Fatal(err)
	}
	path, _ := secretsPath()
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "seed") || strings.Contains(string(b), "azI=") {
		t.Fatalf("a secret is in the file in clear: %s", b)
	}
	if err := SecretDelete("sync-key-2"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := SecretGet("sync-key-2"); ok {
		t.Error("the secret stayed")
	}
}

// a machine without a keychain starts the passphrase vault with a new key,
// a key check from an earlier key stops it (#180)
func TestPassphraseVaultWithoutKeychain(t *testing.T) {
	keyring.MockInitWithError(errors.New("no bus"))
	resetVault(t)
	t.Cleanup(keyring.MockInit)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	pass := "correct horse battery"
	cheapPassphrase(t, &pass)
	if err := SetVaultPassphrase(pass); err != nil {
		t.Fatalf("no keychain: %v", err)
	}
	key, _ := VaultKey()
	forgetVaultKey()
	got, err := VaultKey()
	if err != nil || string(got) != string(key) {
		t.Fatalf("the file does not give the key: %v", err)
	}
	// a key check without the key: refused
	resetVault(t)
	os.Setenv("SSHR_VAULT", "keychain")
	t.Cleanup(func() { os.Unsetenv("SSHR_VAULT") })
	path, _ := keyCheckPath()
	os.WriteFile(path, []byte("0123\n"), 0o600)
	if err := SetVaultPassphrase(pass); !errors.Is(err, ErrVaultKeyLost) {
		t.Fatalf("a key check of a lost key: %v", err)
	}
}

// a keychain that takes the write and keeps nothing leaves the passphrase
// vault and its file as they are (#181)
func TestUseKeychainVerifiesTheKey(t *testing.T) {
	useMockKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	pass := "correct horse battery"
	cheapPassphrase(t, &pass)
	if err := SetVaultPassphrase(pass); err != nil {
		t.Fatal(err)
	}
	old := keychain
	keychain = forgetfulKeychain{}
	t.Cleanup(func() { keychain = old })
	if err := UseKeychainVault(); err == nil {
		t.Fatal("the mode changed though the keychain kept nothing")
	}
	if path, _ := passphraseFilePath(); !fileExists(path) || VaultMode() != VaultPassphrase {
		t.Fatal("the passphrase file or the mode went")
	}
}

// forgetfulKeychain takes every write and keeps nothing
type forgetfulKeychain struct{}

func (forgetfulKeychain) Get(string) (string, error) { return "", keyring.ErrNotFound }
func (forgetfulKeychain) Set(string, string) error   { return nil }
func (forgetfulKeychain) Delete(string) error        { return nil }

// a settings.json that does not read is not replaced with defaults when
// the vault mode changes (#182)
func TestVaultModeKeepsDamagedSettings(t *testing.T) {
	useMockKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	pass := "correct horse battery"
	cheapPassphrase(t, &pass)
	path, _ := settingsPath()
	os.WriteFile(path, []byte("{broken"), 0o600)
	if err := SetVaultPassphrase(pass); err == nil {
		t.Fatal("the mode changed over a settings file that does not read")
	}
	if b, _ := os.ReadFile(path); string(b) != "{broken" {
		t.Fatalf("settings.json was replaced: %s", b)
	}
}

// the limits a vault key file may ask for, and its size (#183)
func TestPassphraseFileTighterLimits(t *testing.T) {
	for _, w := range []*wrappedKey{
		{Version: 1, KDF: "argon2id", Time: 1, MemoryKiB: 512 * 1024, Threads: 1, Salt: make([]byte, 16), Sealed: make([]byte, 64)},
		{Version: 1, KDF: "argon2id", Time: 7, MemoryKiB: 64, Threads: 1, Salt: make([]byte, 16), Sealed: make([]byte, 64)},
		{Version: 1, KDF: "argon2id", Time: 1, MemoryKiB: 64, Threads: 32, Salt: make([]byte, 16), Sealed: make([]byte, 64)},
	} {
		if _, err := unwrapKey(w, "x"); err == nil || !strings.Contains(err.Error(), "out of range") {
			t.Errorf("%+v: %v", w, err)
		}
	}
	resetVault(t)
	path, _ := passphraseFilePath()
	os.WriteFile(path, make([]byte, 5000), 0o600)
	if _, err := readWrappedKey(); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("a big file: %v", err)
	}
}

// a locked keychain may hold the real key, no new key is made then (#184)
func TestPassphraseVaultLockedKeychainMakesNoKey(t *testing.T) {
	keyring.MockInitWithError(fmt.Errorf("failed to unlock correct collection '%v'", "/org/freedesktop/secrets/aliases/default"))
	resetVault(t)
	t.Cleanup(keyring.MockInit)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	pass := "correct horse battery"
	cheapPassphrase(t, &pass)
	err := SetVaultPassphrase(pass)
	if runtime.GOOS == "linux" && !errors.Is(err, ErrKeychainLocked) {
		t.Fatalf("a locked keychain: %v", err)
	}
	if path, _ := passphraseFilePath(); runtime.GOOS == "linux" && fileExists(path) {
		t.Error("a vault key file was written")
	}
}
