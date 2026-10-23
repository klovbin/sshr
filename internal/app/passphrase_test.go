package app

import (
	"encoding/json"
	"errors"
	"os"
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
	if err := SetVaultPassphrase("short"); err == nil {
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
