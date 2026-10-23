package app

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
	argonMaxTime   = 10
	argonMaxMemory = 1024 * 1024
)

// NoTerminalPrompts is set by front ends that own stdin and stdout (mcp),
// the passphrase is then only taken from SSHR_ASKPASS
var NoTerminalPrompts bool

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
	if w.Time == 0 || w.Time > argonMaxTime || w.MemoryKiB < 8 || w.MemoryKiB > argonMaxMemory || w.Threads == 0 || len(w.Salt) < 16 {
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

// askPassphrase gets the passphrase: from the program in SSHR_ASKPASS
// (the app or a script), else on the terminal, never on stdin
var askPassphrase = func(prompt string) (string, error) {
	if prog := os.Getenv("SSHR_ASKPASS"); prog != "" {
		out, err := exec.Command(prog, prompt).Output()
		if err != nil {
			return "", fmt.Errorf("%w: SSHR_ASKPASS failed: %v", ErrNoPassphrase, err)
		}
		return strings.TrimRight(string(out), "\r\n"), nil
	}
	if NoTerminalPrompts {
		return "", fmt.Errorf("%w: the vault needs its passphrase and there is no terminal here, set SSHR_ASKPASS to a program that prints it", ErrNoPassphrase)
	}
	p, err := AskTerminal(prompt)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrNoPassphrase, err)
	}
	return p, nil
}

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
func SetVaultPassphrase(pass string) error {
	if len(pass) < 8 {
		return errors.New("the passphrase is shorter than 8 characters")
	}
	key, err := VaultKey()
	if errors.Is(err, ErrNoKeychain) {
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
	if err := WriteFileAtomic(path, append(b, '\n'), 0o600); err != nil {
		return err
	}
	// a settings file that does not read is not replaced with defaults
	st, err := LoadSettings()
	if err != nil {
		return fmt.Errorf("the vault key is wrapped in %s but settings.json does not read, the mode is not changed: %v", path, err)
	}
	st.Vault = VaultPassphrase
	return SaveSettings(st)
}

// UseKeychainVault stores the current vault key in the system keychain,
// turns the passphrase vault off and removes the vault key file
func UseKeychainVault() error {
	key, err := VaultKey()
	if err != nil {
		return err
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
	st, err := LoadSettings()
	if err != nil {
		return fmt.Errorf("the vault key is in the keychain but settings.json does not read, the mode is not changed: %v", err)
	}
	st.Vault = ""
	if err := SaveSettings(st); err != nil {
		return err
	}
	path, err := passphraseFilePath()
	if err != nil {
		return err
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
	want, err := readKeyCheck()
	if err != nil {
		return nil, err
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
