package app

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// The passphrase vault keeps the vault key in a file wrapped with a key
// derived from a passphrase, for a machine without a system keychain, off
// by default: the passphrase is asked once per process, a forgotten one
// loses every saved secret, and the file can be attacked offline
const (
	VaultKeychain   = "keychain"
	VaultPassphrase = "passphrase"
)

// ErrBadPassphrase means the passphrase does not open the vault key file
var ErrBadPassphrase = errors.New("bad_passphrase")

// ErrNoPassphrase means the passphrase vault is on and there is no way to
// ask for the passphrase here (no terminal, no SSHR_ASKPASS)
var ErrNoPassphrase = errors.New("no_passphrase")

// argonParams are the Argon2id parameters a new file gets, RFC 9106 second
// recommendation, they are stored in the file, tests make them cheap
var argonParams = struct {
	Time, MemoryKiB uint32
	Threads         uint8
}{3, 64 * 1024, 4}

// limits a file may ask for, a crafted file must not make sshr spend
// gigabytes or minutes before the passphrase is even checked
const (
	argonMaxTime    = 6
	argonMaxMemory  = 256 * 1024
	argonMaxThreads = 16
	// passphraseFileMax is more than a wrapped key ever needs
	passphraseFileMax = 4096
	// passphraseMin is the shortest passphrase taken, the file can be
	// attacked offline
	passphraseMin = 12
)

// wrappedKey is ~/.sshr/vault/vault-key.json
type wrappedKey struct {
	Version   int    `json:"version"`
	KDF       string `json:"kdf"`
	Time      uint32 `json:"t"`
	MemoryKiB uint32 `json:"m"`
	Threads   uint8  `json:"p"`
	Salt      []byte `json:"salt"`
	Sealed    []byte `json:"sealed"`
}

var wrapAAD = []byte("sshr/vault-key/v1")

func passphraseFilePath() (string, error) {
	lock, err := vaultLockPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(lock), "vault-key.json"), nil
}

// VaultMode is where the vault key lives: SSHR_VAULT, then the setting,
// the keychain by default
func VaultMode() string {
	if m := os.Getenv("SSHR_VAULT"); m == VaultPassphrase || m == VaultKeychain {
		return m
	}
	if st, err := LoadSettings(); err == nil && st.Vault == VaultPassphrase {
		return VaultPassphrase
	}
	return VaultKeychain
}

func wrapKey(key []byte, pass string) (*wrappedKey, error) {
	w := &wrappedKey{Version: 1, KDF: "argon2id", Time: argonParams.Time, MemoryKiB: argonParams.MemoryKiB, Threads: argonParams.Threads, Salt: make([]byte, 16)}
	if _, err := rand.Read(w.Salt); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(argon2.IDKey([]byte(pass), w.Salt, w.Time, w.MemoryKiB, w.Threads, chacha20poly1305.KeySize))
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	w.Sealed = aead.Seal(nonce, nonce, key, wrapAAD)
	return w, nil
}

func unwrapKey(w *wrappedKey, pass string) ([]byte, error) {
	if w.Version != 1 || w.KDF != "argon2id" {
		return nil, fmt.Errorf("the vault key file has format %d and kdf %q, this sshr reads format 1 with argon2id", w.Version, w.KDF)
	}
	if w.Time == 0 || w.Time > argonMaxTime || w.MemoryKiB < 8 || w.MemoryKiB > argonMaxMemory || w.Threads == 0 || w.Threads > argonMaxThreads || len(w.Salt) < 16 || len(w.Salt) > 64 {
		return nil, errors.New("the vault key file asks for Argon2 parameters out of range")
	}
	aead, err := chacha20poly1305.NewX(argon2.IDKey([]byte(pass), w.Salt, w.Time, w.MemoryKiB, w.Threads, chacha20poly1305.KeySize))
	if err != nil {
		return nil, err
	}
	if len(w.Sealed) < aead.NonceSize() {
		return nil, errors.New("the vault key file is damaged")
	}
	key, err := aead.Open(nil, w.Sealed[:aead.NonceSize()], w.Sealed[aead.NonceSize():], wrapAAD)
	if err != nil {
		return nil, ErrBadPassphrase
	}
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("the vault key file is damaged")
	}
	return key, nil
}

func readWrappedKey() (*wrappedKey, error) {
	path, err := passphraseFilePath()
	if err != nil {
		return nil, err
	}
	b, err := ReadFileShared(path)
	if err == nil && len(b) > passphraseFileMax {
		return nil, fmt.Errorf("%s is larger than a vault key file can be", path)
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("the vault is set to a passphrase but %s is missing, run sshr vault passphrase on this machine or set SSHR_VAULT=keychain", path)
	}
	if err != nil {
		return nil, err
	}
	var w wrappedKey
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, fmt.Errorf("%s is damaged: %v", path, err)
	}
	return &w, nil
}

// askPassphrase gets the passphrase, promptPassphrase asks the user, a
// test answers it itself
var askPassphrase = promptPassphrase

// passphraseVaultKey opens the vault key file with the passphrase
func passphraseVaultKey() ([]byte, error) {
	w, err := readWrappedKey()
	if err != nil {
		return nil, err
	}
	pass, err := askPassphrase("sshr vault passphrase: ")
	if err != nil {
		return nil, err
	}
	return unwrapKey(w, pass)
}

// SetVaultPassphrase wraps the current vault key with pass into the vault
// key file and turns the passphrase vault on, the key stays the same, so
// every saved secret still opens, a key in the system keychain stays there,
// the named secrets are moved by MoveSecrets
func SetVaultPassphrase(pass string, secretNames []string) error {
	// one mode change at a time, the setting and the files must agree
	unlock, err := vaultModeLock()
	if err != nil {
		return err
	}
	defer unlock()
	if len(pass) < passphraseMin {
		return fmt.Errorf("the passphrase is shorter than %d characters, the file it guards can be attacked offline", passphraseMin)
	}
	key, err := VaultKey()
	// a locked keychain or one that did not answer may hold the real key,
	// only a keychain that is not there starts with a new one
	if errors.Is(err, ErrNoKeychain) && !errors.Is(err, ErrKeychainLocked) && !errors.Is(err, ErrKeychainTimeout) {
		// a machine without a keychain, the case the passphrase vault is
		// for, starts with a new key, unless a key check says secrets were
		// sealed here with a key that is now out of reach
		key, err = newVaultKeyWithoutKeychain()
	}
	if err != nil {
		return err
	}
	w, err := wrapKey(key, pass)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	path, err := passphraseFilePath()
	if err != nil {
		return err
	}
	// a passphrase changed again replaces the only wrapped copy of the key,
	// a failed change puts the old file back instead of removing it
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	undo := func() {
		if old != nil {
			WriteFileAtomic(path, old, 0o600)
		} else {
			os.Remove(path)
		}
	}
	if err := WriteFileAtomic(path, append(b, '\n'), 0o600); err != nil {
		return err
	}
	// the named secrets move before the mode changes, the mode never points
	// at a file that does not hold them
	moved, err := moveSecretsBack(secretNames, true)
	if err != nil {
		undo()
		return fmt.Errorf("the sync keys did not move, nothing is changed: %v", err)
	}
	// a settings file that does not read is not replaced with defaults, the
	// keys this call moved go back to the keychain the mode still reads
	st, err := LoadSettings()
	if err == nil {
		st.Vault = VaultPassphrase
		if err = SaveSettings(st); err == nil {
			return nil
		}
	}
	if berr := MoveSecrets(moved, false); berr != nil {
		return fmt.Errorf("settings.json was not saved and the sync keys did not go back to the keychain, fix settings.json and run the same command again: %v, %v", err, berr)
	}
	return fmt.Errorf("the vault key is wrapped in %s but settings.json was not saved, the mode is not changed: %v", path, err)
}

// UseKeychainVault stores the current vault key in the system keychain,
// turns the passphrase vault off and removes the vault key file
func UseKeychainVault(secretNames []string) error {
	unlock, err := vaultModeLock()
	if err != nil {
		return err
	}
	defer unlock()
	key, err := VaultKey()
	if err != nil {
		return err
	}
	// another key in the keychain sealed other secrets, it is not replaced,
	// a keychain that cannot say what it holds is not written either
	other, ok, err := getVaultKey()
	if err != nil {
		return err
	}
	if ok && !bytes.Equal(other, key) {
		return fmt.Errorf("%w: the keychain holds another vault key, it may have sealed secrets of its own, remove the keychain item sshr/vault-key first if it is not needed", ErrVaultKeyLost)
	}
	if err := SecretSet(keyringUser, key); err != nil {
		return err
	}
	// a keychain may take a write and keep nothing (a session collection,
	// a locked one), the file is the only copy until the key reads back
	if kept, ok, err := getVaultKey(); err != nil || !ok || !bytes.Equal(kept, key) {
		if err == nil {
			err = errors.New("the keychain did not keep the vault key, the passphrase vault stays")
		}
		return err
	}
	// every secret the file holds goes back, a profile with another prefix
	// or an epoch state.json does not list yet is not left behind
	secretNames, err = withFileSecrets(secretNames)
	if err != nil {
		return err
	}
	moved, err := moveSecretsBack(secretNames, false)
	if err != nil {
		return fmt.Errorf("the sync keys did not move to the keychain, the passphrase vault stays: %v", err)
	}
	st, err := LoadSettings()
	if err == nil {
		st.Vault = ""
		err = SaveSettings(st)
	}
	if err != nil {
		// the mode still reads the file, the keys this call moved go back
		if berr := MoveSecrets(moved, true); berr != nil {
			return fmt.Errorf("settings.json was not saved and the sync keys did not go back to the secrets file, fix settings.json and run the same command again: %v, %v", err, berr)
		}
		return fmt.Errorf("the vault key is in the keychain but settings.json was not saved, the mode is not changed: %v", err)
	}
	path, err := passphraseFilePath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// the secrets moved out, a stale copy would come back on the next switch
	return removeEmptySecrets()
}

// withFileSecrets adds the names secrets.json holds to names
func withFileSecrets(names []string) ([]string, error) {
	path, err := secretsPath()
	if err != nil {
		return nil, err
	}
	f, err := readSecrets(path)
	if err != nil {
		return nil, err
	}
	out := append([]string(nil), names...)
	for _, n := range slices.Sorted(maps.Keys(f.Secrets)) {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out, nil
}

// removeEmptySecrets removes secrets.json under its lock, a secret another
// process wrote there after the move keeps the file
func removeEmptySecrets() error {
	path, err := secretsPath()
	if err != nil {
		return err
	}
	unlock, err := waitLock(path+".lock", "saving a secret", secretsWait)
	if err != nil {
		return err
	}
	defer unlock()
	f, err := readSecrets(path)
	if err != nil {
		return err
	}
	if len(f.Secrets) > 0 {
		return fmt.Errorf("%s got %d secrets while the vault moved to the keychain, run sshr vault keychain again to move them", path, len(f.Secrets))
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// newVaultKeyWithoutKeychain makes a vault key for a machine without a
// keychain, refused when a key check exists, a new key would leave the
// secrets sealed with the old one unreadable
func newVaultKeyWithoutKeychain() ([]byte, error) {
	vaultMu.Lock()
	defer vaultMu.Unlock()
	if vaultKey != nil {
		return vaultKey, nil
	}
	if keySetPending {
		return nil, keychainError(fmt.Errorf("%w: a vault key may still reach the keychain from a call that ran out of time, start sshr again", errKeyringTimeout))
	}
	want, err := readKeyCheck()
	if err != nil {
		return nil, err
	}
	if want == "" && sealedSecretsHere() {
		return nil, fmt.Errorf("%w: host files here hold secrets sealed with a vault key the keychain does not give now, bring the keychain back before moving the key under a passphrase", ErrVaultKeyLost)
	}
	if want != "" {
		path, _ := keyCheckPath()
		return nil, fmt.Errorf("%w: secrets here were sealed with a vault key the keychain does not give now, bring the keychain back before moving the key under a passphrase, or delete %s and save the passwords and keys again", ErrVaultKeyLost, path)
	}
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := checkVaultKey(key); err != nil {
		return nil, err
	}
	vaultKey = key
	return key, nil
}

// vaultModeLock is held while the vault mode changes, it is not the lock
// createVaultKey takes, VaultKey may create a key inside a mode change
func vaultModeLock() (func(), error) {
	lock, err := vaultLockPath()
	if err != nil {
		return nil, err
	}
	return waitLock(filepath.Join(filepath.Dir(lock), ".mode.lock"), "changing the vault mode", 10*time.Second)
}

// sealedSecretsHere tells whether any host file holds a sealed password
// or key, a vault key made now could not open them
func sealedSecretsHere() bool {
	lock, err := vaultLockPath()
	if err != nil {
		return true
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(lock), "hosts", "*.json"))
	if err != nil {
		return true
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return true
		}
		// only the sealed fields count, a note that starts like a sealed
		// value does not, a file that does not parse counts as sealed
		var h struct {
			PasswordSealed string `json:"password_sealed"`
			KeySealed      string `json:"key_sealed"`
		}
		if json.Unmarshal(b, &h) != nil {
			return true
		}
		for _, v := range []string{h.PasswordSealed, h.KeySealed} {
			if strings.HasPrefix(v, sealPrefix) || strings.HasPrefix(v, sealPrefix2) {
				return true
			}
		}
	}
	return false
}
