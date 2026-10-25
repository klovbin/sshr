package vault

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
	"sshr.dev/internal/settings"
)

// cheapPassphrase makes Argon2 fast and answers the prompt with pass
func cheapPassphrase(t *testing.T, pass *string) {
	t.Helper()
	old, oldAsk := argonParams, askPassphrase
	argonParams.Time, argonParams.MemoryKiB, argonParams.Threads = 1, 8, 1
	askPassphrase = func(string) (string, error) { return *pass, nil }
	t.Cleanup(func() { argonParams, askPassphrase = old, oldAsk })
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
	key, err := Key()
	if err != nil {
		t.Fatal(err)
	}
	if err := SetPassphrase("short pass", nil); err == nil {
		t.Error("a short passphrase was taken")
	}
	if err := SetPassphrase(pass, nil); err != nil {
		t.Fatal(err)
	}
	if Mode() != ModePassphrase {
		t.Fatalf("mode %s", Mode())
	}
	// the keychain keeps no copy that opens the secrets without the
	// passphrase (#367)
	if _, ok, err := getVaultKey(); ok || err != nil {
		t.Fatalf("the keychain still gives the vault key: %v %v", ok, err)
	}
	// a machine without a keychain
	keyring.MockInitWithError(errors.New("no bus"))
	t.Cleanup(keyring.MockInit)
	forgetVaultKey()
	got, err := Key()
	if err != nil || string(got) != string(key) {
		t.Fatalf("the file did not give the same key: %v", err)
	}
	forgetVaultKey()
	pass = "wrong"
	if _, err := Key(); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("a wrong passphrase: %v", err)
	}
	if _, ok, _ := getVaultKey(); ok {
		t.Error("a key was made")
	}
	// back to the keychain
	keyring.MockInit()
	pass = "correct horse battery"
	forgetVaultKey()
	if err := UseKeychain(nil); err != nil {
		t.Fatal(err)
	}
	if Mode() != ModeKeychain {
		t.Errorf("mode %s", Mode())
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
	if err := SetPassphrase(pass, []string{"sync-device", "sync-key-1"}); err != nil {
		t.Fatal(err)
	}
	// the keychain copy is gone once the file holds it (#187)
	if _, err := keyring.Get(keyringService, "sync-device"); err == nil {
		t.Error("the sync key stayed in the keychain")
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
	if err := SetPassphrase(pass, nil); err != nil {
		t.Fatalf("no keychain: %v", err)
	}
	key, _ := Key()
	forgetVaultKey()
	got, err := Key()
	if err != nil || string(got) != string(key) {
		t.Fatalf("the file does not give the key: %v", err)
	}
	// a key check without the key: refused
	resetVault(t)
	os.Setenv("SSHR_VAULT", "keychain")
	t.Cleanup(func() { os.Unsetenv("SSHR_VAULT") })
	path, _ := keyCheckPath()
	os.WriteFile(path, []byte("0123\n"), 0o600)
	if err := SetPassphrase(pass, nil); !errors.Is(err, ErrVaultKeyLost) {
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
	if err := SetPassphrase(pass, nil); err != nil {
		t.Fatal(err)
	}
	old := keychain
	keychain = forgetfulKeychain{}
	t.Cleanup(func() { keychain = old })
	if err := UseKeychain(nil); err == nil {
		t.Fatal("the mode changed though the keychain kept nothing")
	}
	if path, _ := passphraseFilePath(); !fileExists(path) || Mode() != ModePassphrase {
		t.Fatal("the passphrase file or the mode went")
	}
}

// forgetfulKeychain takes every write and keeps nothing
type forgetfulKeychain struct{}

func (forgetfulKeychain) Get(string) (string, error) { return "", ErrSecretNotFound }
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
	path, _ := settings.Path()
	os.WriteFile(path, []byte("{broken"), 0o600)
	if err := SetPassphrase(pass, nil); err == nil {
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
	os.WriteFile(path, make([]byte, keyFileMax+1), 0o600)
	if _, _, err := readKeyFile(); err == nil || !strings.Contains(err.Error(), "larger") {
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
	err := SetPassphrase(pass, nil)
	if runtime.GOOS == "linux" && !errors.Is(err, ErrKeychainLocked) {
		t.Fatalf("a locked keychain: %v", err)
	}
	if path, _ := passphraseFilePath(); runtime.GOOS == "linux" && fileExists(path) {
		t.Error("a vault key file was written")
	}
}

// no new key over host files that hold sealed secrets, no keychain key
// replaced by another one (#185)
func TestVaultModeKeepsKeysThatSealed(t *testing.T) {
	keyring.MockInitWithError(errors.New("no bus"))
	resetVault(t)
	t.Cleanup(keyring.MockInit)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	pass := "correct horse battery"
	cheapPassphrase(t, &pass)
	lock, _ := vaultLockPath()
	hosts := filepath.Join(filepath.Dir(lock), "hosts")
	os.MkdirAll(hosts, 0o700)
	os.WriteFile(filepath.Join(hosts, "a.json"), []byte(`{"password_sealed": "v2:abc"}`), 0o600)
	if err := SetPassphrase(pass, nil); !errors.Is(err, ErrVaultKeyLost) {
		t.Fatalf("a new key over sealed secrets: %v", err)
	}
	// another key in the keychain is not replaced
	os.Remove(filepath.Join(hosts, "a.json"))
	keyring.MockInit()
	resetVault(t)
	if err := SetPassphrase(pass, nil); err != nil {
		t.Fatal(err)
	}
	keyring.Set(keyringService, keyringUser, base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err := UseKeychain(nil); !errors.Is(err, ErrVaultKeyLost) {
		t.Fatalf("another keychain key was replaced: %v", err)
	}
}

// a move back to the keychain takes the sync keys along and removes the
// secrets file, a stale copy does not come back later (#186, #187)
func TestUseKeychainMovesSecretsBack(t *testing.T) {
	useMockKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	pass := "correct horse battery"
	cheapPassphrase(t, &pass)
	SecretSet("sync-device", []byte("seed"))
	names := []string{"sync-device"}
	if err := SetPassphrase(pass, names); err != nil {
		t.Fatal(err)
	}
	if err := UseKeychain(names); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := SecretGet("sync-device"); err != nil || !ok || string(v) != "seed" {
		t.Fatalf("%q %v %v", v, ok, err)
	}
	if sp, _ := secretsPath(); fileExists(sp) {
		t.Error("secrets.json stayed")
	}
}

// a moved secret is removed from where it came from once the new place
// reads it back (#187)
func TestMoveSecretsRemovesTheSource(t *testing.T) {
	useMockKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	pass := "correct horse battery"
	cheapPassphrase(t, &pass)
	SecretSet("sync-device", []byte("seed"))
	if _, err := Key(); err != nil {
		t.Fatal(err)
	}
	if err := MoveSecrets([]string{"sync-device"}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := keyring.Get(keyringService, "sync-device"); err == nil {
		t.Error("the keychain copy stayed")
	}
	if v, err := (fileKeychain{}).Get("sync-device"); err != nil || v == "" {
		t.Fatalf("the file does not hold it: %v", err)
	}
}

// pickyKeychain refuses to read the names in fail and passes the rest on
type pickyKeychain struct {
	Keychain
	fail map[string]bool
}

func (k pickyKeychain) Get(name string) (string, error) {
	if k.fail[name] {
		return "", errors.New("locked")
	}
	return k.Keychain.Get(name)
}

// a passphrase change that fails keeps the old vault key file, it is the
// only wrapped copy of the key (#188)
func TestPassphraseChangeFailureKeepsOldFile(t *testing.T) {
	useMockKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	pass := "correct horse battery"
	cheapPassphrase(t, &pass)
	key, err := Key()
	if err != nil {
		t.Fatal(err)
	}
	if err := SetPassphrase(pass, nil); err != nil {
		t.Fatal(err)
	}
	SecretSet("sync-device", []byte("seed"))
	old := keychain
	keychain = pickyKeychain{old, map[string]bool{"sync-device": true}}
	t.Cleanup(func() { keychain = old })
	if err := SetPassphrase("another long passphrase", []string{"sync-device"}); err == nil {
		t.Fatal("the change went through a key that does not read")
	}
	keyring.MockInitWithError(errors.New("no bus"))
	t.Cleanup(keyring.MockInit)
	forgetVaultKey()
	got, err := Key()
	if err != nil || string(got) != string(key) {
		t.Fatalf("the old passphrase does not open the vault key now: %v", err)
	}
}

// a sync key move that fails halfway takes back the keys it moved, the
// mode did not change and still reads the keychain (#190)
func TestFailedMoveTakesKeysBack(t *testing.T) {
	useMockKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	pass := "correct horse battery"
	cheapPassphrase(t, &pass)
	SecretSet("sync-device", []byte("seed"))
	SecretSet("sync-key-1", []byte("k1"))
	old := keychain
	keychain = pickyKeychain{old, map[string]bool{"sync-key-1": true}}
	t.Cleanup(func() { keychain = old })
	if err := SetPassphrase(pass, []string{"sync-device", "sync-key-1"}); err == nil {
		t.Fatal("the change went through a key that does not read")
	}
	keychain = old
	if Mode() == ModePassphrase {
		t.Fatal("the mode changed")
	}
	if v, ok, err := SecretGet("sync-device"); err != nil || !ok || string(v) != "seed" {
		t.Fatalf("the moved key is not back in the keychain: %q %v %v", v, ok, err)
	}
	if _, err := (fileKeychain{}).Get("sync-device"); err == nil {
		t.Error("a copy stayed in the secrets file")
	}
}

// settings.json that does not save after the move sends the keys back
// (#190)
func TestSettingsFailureTakesKeysBack(t *testing.T) {
	useMockKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	pass := "correct horse battery"
	cheapPassphrase(t, &pass)
	SecretSet("sync-device", []byte("seed"))
	path, _ := settings.Path()
	os.WriteFile(path, []byte("{broken"), 0o600)
	if err := SetPassphrase(pass, []string{"sync-device"}); err == nil {
		t.Fatal("the mode changed over a settings file that does not read")
	}
	if _, err := keyring.Get(keyringService, "sync-device"); err != nil {
		t.Fatalf("the key did not come back to the keychain: %v", err)
	}
}

// a move back to the keychain takes every secret of the file, also one
// under a name sshr did not list (#189)
func TestUseKeychainMovesEverySecret(t *testing.T) {
	useMockKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	pass := "correct horse battery"
	cheapPassphrase(t, &pass)
	if err := SetPassphrase(pass, nil); err != nil {
		t.Fatal(err)
	}
	SecretSet("sync-device", []byte("seed"))
	SecretSet("work-sync-device", []byte("seed2"))
	if err := UseKeychain([]string{"sync-device"}); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := SecretGet("work-sync-device"); err != nil || !ok || string(v) != "seed2" {
		t.Fatalf("a secret the names did not list was lost: %q %v %v", v, ok, err)
	}
	if sp, _ := secretsPath(); fileExists(sp) {
		t.Error("secrets.json stayed")
	}
}

// only the sealed fields of a host file count as sealed secrets, a note
// that starts like a sealed value does not (#191)
func TestSealedSecretsHereReadsFields(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	lock, err := vaultLockPath()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(filepath.Dir(lock), "hosts")
	os.MkdirAll(dir, 0o700)
	file := filepath.Join(dir, "a.json")
	os.WriteFile(file, []byte(`{"id":"a","notes":"v1: rack 4"}`), 0o600)
	if sealedSecretsHere() {
		t.Error("a note was taken for a sealed secret")
	}
	os.WriteFile(file, []byte(`{"id":"a","password_sealed":"v2:abc"}`), 0o600)
	if !sealedSecretsHere() {
		t.Error("a sealed password was missed")
	}
}

// a keychain whose vault key does not read is not written over (#192)
func TestUseKeychainKeepsKeyThatDoesNotRead(t *testing.T) {
	useMockKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	pass := "correct horse battery"
	cheapPassphrase(t, &pass)
	if err := SetPassphrase(pass, nil); err != nil {
		t.Fatal(err)
	}
	other := base64.StdEncoding.EncodeToString(make([]byte, 32))
	keyring.Set(keyringService, keyringUser, other)
	old := keychain
	keychain = pickyKeychain{old, map[string]bool{keyringUser: true}}
	t.Cleanup(func() { keychain = old })
	if err := UseKeychain(nil); err == nil {
		t.Fatal("the mode changed over a keychain that did not read")
	}
	if v, _ := keyring.Get(keyringService, keyringUser); v != other {
		t.Error("the keychain item was written over")
	}
}

// a passphrase changed again with settings.json that does not save leaves
// the sync keys in the file the mode reads, they were never moved (#193)
func TestPassphraseChangeKeepsKeysInFile(t *testing.T) {
	useMockKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	pass := "correct horse battery"
	cheapPassphrase(t, &pass)
	if err := SetPassphrase(pass, nil); err != nil {
		t.Fatal(err)
	}
	// the mode stays readable once settings.json breaks
	t.Setenv("SSHR_VAULT", "passphrase")
	if err := SecretSet("sync-device", []byte("seed")); err != nil {
		t.Fatal(err)
	}
	path, _ := settings.Path()
	os.WriteFile(path, []byte("{broken"), 0o600)
	if err := SetPassphrase("another long passphrase", []string{"sync-device"}); err == nil {
		t.Fatal("the change went through a settings file that does not read")
	}
	if _, err := (fileKeychain{}).Get("sync-device"); err != nil {
		t.Fatalf("the key left the secrets file: %v", err)
	}
	if _, err := keyring.Get(keyringService, "sync-device"); err == nil {
		t.Error("the key went to the keychain the mode does not read")
	}
}

// a secret that does not read is named when it stops a move (#194)
func TestMoveNamesSecretThatDoesNotRead(t *testing.T) {
	useMockKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	pass := "correct horse battery"
	cheapPassphrase(t, &pass)
	SecretSet("sync-key-7", []byte("k7"))
	old := keychain
	keychain = pickyKeychain{old, map[string]bool{"sync-key-7": true}}
	t.Cleanup(func() { keychain = old })
	err := SetPassphrase(pass, []string{"sync-key-7"})
	if err == nil || !strings.Contains(err.Error(), "sync-key-7") {
		t.Fatalf("the error does not name the secret: %v", err)
	}
}

func forgetVaultKey() {
	vaultMu.Lock()
	vaultKey = nil
	vaultMu.Unlock()
}

// a keychain error that does not say the keychain is missing leaves the
// copy and says so, it is never taken as removed, a keychain that holds
// another vault key keeps it (#367)
func TestPassphraseVaultKeepsCopyItCannotRemove(t *testing.T) {
	useMockKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	pass := "correct horse battery"
	cheapPassphrase(t, &pass)
	if _, err := Key(); err != nil {
		t.Fatal(err)
	}
	keyring.MockInitWithError(errors.New("org.freedesktop.DBus.Error.AccessDenied"))
	t.Cleanup(keyring.MockInit)
	if err := SetPassphrase(pass, nil); !errors.Is(err, ErrKeychainCopyLeft) {
		t.Fatalf("an error of a keychain that is there: %v", err)
	}
	if Mode() != ModePassphrase {
		t.Errorf("mode %s", Mode())
	}

	keyring.MockInit()
	key, _ := Key()
	other := make([]byte, len(key))
	keyring.Set("sshr", keyringUser, base64.StdEncoding.EncodeToString(other))
	if err := dropKeychainCopy(key); !errors.Is(err, ErrKeychainCopyLeft) {
		t.Fatalf("another key in the keychain: %v", err)
	}
	if k, ok, _ := getVaultKey(); !ok || string(k) != string(other) {
		t.Error("another vault key was removed")
	}
}

// a keychain that is there and fails gives no new vault key, it may hold
// the real one (#368)
func TestPassphraseVaultMakesNoKeyOnKeychainError(t *testing.T) {
	keyring.MockInitWithError(errors.New("org.freedesktop.DBus.Error.AccessDenied"))
	resetVault(t)
	t.Cleanup(keyring.MockInit)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	pass := "correct horse battery"
	cheapPassphrase(t, &pass)
	if err := SetPassphrase(pass, nil); err == nil {
		t.Fatal("a vault key was made while the keychain failed")
	}
	if path, _ := passphraseFilePath(); fileExists(path) {
		t.Error("a vault key file was written")
	}
	if Mode() != ModeKeychain {
		t.Errorf("mode %s", Mode())
	}
}

// a passphrase of few different characters is refused however long
func TestPassphraseNeedsDifferentCharacters(t *testing.T) {
	useMockKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	pass := "correct horse battery"
	cheapPassphrase(t, &pass)
	if err := SetPassphrase("abababababababab", nil); err == nil || !strings.Contains(err.Error(), "different characters") {
		t.Fatalf("a passphrase of two characters: %v", err)
	}
}
