// Package vault keeps the secrets of sshr: the vault key in a keychain or
// under a passphrase, seals for passwords and keys bound to their host,
// named secrets of the sync device, it runs no program, the system
// keychain and the passphrase prompt are set by the front ends
package vault

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"sshr.dev/internal/fileio"
)

// The vault key encrypts saved passwords and keys inside host files, it is
// 32 random bytes kept in the system keychain (Secret Service on Linux,
// Keychain on macOS, Credential Manager on Windows), never on disk
const (
	keyringService = "sshr"
	keyringUser    = "vault-key"
	SealPrefix     = "v1:"
	// SealPrefix2 marks a value sealed together with the destination it
	// belongs to, see SealFor
	SealPrefix2 = "v2:"
)

// keyringTimeout bounds every keychain call, a locked Secret Service
// collection waits for an unlock prompt with no timeout of its own, over ssh
// or with no desktop nobody answers it
var keyringTimeout = 5 * time.Second

// ErrNoKeychain means there is no system keychain to keep the vault key in,
// saved passwords and keys are unavailable then, asking for the password
// and key files still work
var ErrNoKeychain = errors.New("no_keychain")

// The states of a keychain that cannot be used, every one is ErrNoKeychain
// too, so a caller that only knows that one still works
var (
	// ErrKeychainMissing means there is no keychain service to ask: no
	// session bus, no Secret Service running, no default collection
	ErrKeychainMissing = errors.New("keychain_missing")
	// ErrKeychainLocked means the keychain is there and locked, its unlock
	// prompt was dismissed
	ErrKeychainLocked = errors.New("keychain_locked")
	// ErrKeychainTimeout means the keychain did not answer in time, an
	// unlock prompt nobody sees (over ssh, with no desktop)
	ErrKeychainTimeout = errors.New("keychain_timeout")
)

// KeychainError carries why the keychain could not be used, State is one
// of the states above when it is known
type KeychainError struct {
	Err   error
	State error
}

func keychainError(err error) *KeychainError {
	e := &KeychainError{Err: err}
	if errors.Is(err, errKeyringTimeout) {
		e.State = ErrKeychainTimeout
	} else if sk, ok := keychain.(stateKeychain); ok {
		e.State = sk.State(err)
	}
	return e
}

func (e *KeychainError) Error() string {
	switch e.State {
	case ErrKeychainLocked:
		return "the system keychain is locked (" + e.Err.Error() + "), unlock it and try again, saved passwords need it"
	case ErrKeychainTimeout:
		return "the system keychain did not answer in " + keyringTimeout.String() + ", it may be waiting for an unlock nobody sees (over ssh or with no desktop), unlock it on the desktop or ask for the password each time"
	}
	return "the system keychain is not available (" + e.Err.Error() + "), saved passwords need it, ask for the password each time or use a key file"
}

func (e *KeychainError) Unwrap() []error {
	if e.State != nil {
		return []error{ErrNoKeychain, e.State, e.Err}
	}
	return []error{ErrNoKeychain, e.Err}
}

var (
	vaultMu  sync.Mutex
	vaultKey []byte
	// vaultLockPath is where the lock against two processes creating the
	// vault key at once lives, tests point it elsewhere
	vaultLockPath = func() (string, error) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir := filepath.Join(home, ".sshr", "vault")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		return filepath.Join(dir, ".lock"), nil
	}
)

// keySetPending is set when storing a new vault key ran out of time, the
// store may still land, this process makes no other key, under vaultMu
var keySetPending bool

// errKeyringTimeout is a keychain call that did not answer in time
var errKeyringTimeout = errors.New("no answer from the keychain, is it locked?")

// keyringQuiet is how long the keychain is not asked again after a call
// timed out, every call would wait the full timeout and leave a goroutine
// behind, a sync of many hosts would take minutes
const keyringQuiet = time.Minute

var (
	keyringMu        sync.Mutex
	keyringDownUntil time.Time
)

// keyringCall runs f with keyringTimeout, the goroutine of a call that
// timed out is left behind, it is blocked on D-Bus and holds nothing,
// after a timeout calls fail at once for keyringQuiet
func keyringCall(f func() (string, error)) (string, error) {
	keyringMu.Lock()
	down := time.Now().Before(keyringDownUntil)
	keyringMu.Unlock()
	if down {
		return "", errKeyringTimeout
	}
	type result struct {
		v   string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		v, err := f()
		if err == nil {
			// an answer, even one that came after the time limit (an unlock
			// typed late), ends the quiet period
			keyringMu.Lock()
			keyringDownUntil = time.Time{}
			keyringMu.Unlock()
		}
		ch <- result{v, err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-time.After(keyringTimeout):
		keyringMu.Lock()
		keyringDownUntil = time.Now().Add(keyringQuiet)
		keyringMu.Unlock()
		return "", errKeyringTimeout
	}
}

func getVaultKey() ([]byte, bool, error) {
	key, ok, err := SecretGet(keyringUser)
	if err != nil || !ok {
		return nil, false, err
	}
	if len(key) != chacha20poly1305.KeySize {
		return nil, false, keychainError(errors.New("the vault key in the keychain is damaged"))
	}
	return key, true, nil
}

// Key returns a copy of the vault key, creating it on first use, the
// keychain is read once per process and again after the key was dropped
// when idle, the copy is the caller's, the cached key may be zeroed by the
// idle drop at any time after the call
func Key() ([]byte, error) {
	vaultMu.Lock()
	defer vaultMu.Unlock()
	if vaultKey != nil {
		touchKey()
		return bytes.Clone(vaultKey), nil
	}
	var key []byte
	if Mode() == ModePassphrase {
		// the passphrase vault never makes a key, it opens the one its
		// file holds or fails
		k, err := passphraseVaultKey()
		if err != nil {
			return nil, err
		}
		key = k
	} else {
		k, ok, err := getVaultKey()
		if err != nil {
			return nil, err
		}
		if !ok {
			if k, err = createVaultKey(); err != nil {
				return nil, err
			}
		}
		key = k
	}
	if err := checkVaultKey(key); err != nil {
		return nil, err
	}
	vaultKey = key
	touchKey()
	return bytes.Clone(key), nil
}

// ErrVaultKeyLost means the keychain no longer holds the vault key the
// saved secrets were sealed with, or holds another one
var ErrVaultKeyLost = errors.New("vault_key_lost")

// keyCheckPath is the file that tells which vault key the secrets on this
// machine were sealed with, a hash of the key and not the key, it sits
// next to the lock
func keyCheckPath() (string, error) {
	lock, err := vaultLockPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(lock), "key-check"), nil
}

func keyCheckValue(key []byte) string {
	sum := sha256.Sum256(append([]byte("sshr vault key check\x00"), key...))
	return hex.EncodeToString(sum[:16])
}

// readKeyCheck returns the recorded check value, empty when none is kept
func readKeyCheck() (string, error) {
	path, err := keyCheckPath()
	if err != nil {
		return "", err
	}
	b, err := fileio.ReadFileShared(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	return strings.TrimSpace(string(b)), err
}

// checkVaultKey compares key with the one the secrets here were sealed
// with, the first key seen is recorded, a keychain that lost its item or
// was swapped for another (gnome-keyring for KeePassXC) is told apart
// from a first start instead of sealing everything anew with a second key
func checkVaultKey(key []byte) error {
	want, err := readKeyCheck()
	if err != nil {
		return err
	}
	got := keyCheckValue(key)
	if want == "" {
		// recording is best effort, a disk that takes no write must not
		// keep a working key from opening the secrets, the check only
		// starts protecting once it is written
		if path, err := keyCheckPath(); err == nil {
			if err := fileio.WriteFile(path, []byte(got+"\n"), 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "sshr: could not record the vault key check: %v\n", err)
			}
		}
		return nil
	}
	if want != got {
		path, _ := keyCheckPath()
		return fmt.Errorf("%w: the system keychain holds another vault key than the one the saved passwords and keys here were sealed with (a reset keychain or another keychain program), bring back the keychain item sshr/vault-key, if that key is the right one deleting %s is enough, otherwise delete it and save the passwords and keys again", ErrVaultKeyLost, path)
	}
	return nil
}

// createVaultKey makes the vault key under a file lock, two processes
// starting at once would otherwise each store their own key and the
// secrets sealed with the losing one could not be opened again
func createVaultKey() ([]byte, error) {
	path, err := vaultLockPath()
	if err != nil {
		return nil, err
	}
	unlock, err := fileio.LockFile(path)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if key, ok, err := getVaultKey(); err != nil || ok {
		return key, err
	}
	// a check value without a key in the keychain means the key was lost,
	// a new one would make every saved secret here unreadable for good
	if want, err := readKeyCheck(); err != nil {
		return nil, err
	} else if want != "" {
		path, _ := keyCheckPath()
		return nil, fmt.Errorf("%w: the system keychain lost the vault key the saved passwords and keys here were sealed with (a reset keychain or another keychain program), bring back the keychain item sshr/vault-key, or delete %s and save the passwords and keys again", ErrVaultKeyLost, path)
	}
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if keySetPending {
		return nil, keychainError(fmt.Errorf("%w: a new vault key may still reach the keychain from a call that ran out of time, start sshr again", errKeyringTimeout))
	}
	if err := SecretSet(keyringUser, key); err != nil {
		if errors.Is(err, ErrKeychainTimeout) {
			// the call may still complete with this key, another key made
			// later in this process could be overwritten by it
			keySetPending = true
		}
		return nil, err
	}
	// read back what the keychain holds, that is the key every other process
	// will get
	key, ok, err := getVaultKey()
	if err == nil && !ok {
		err = keychainError(errors.New("the vault key was not kept"))
	}
	return key, err
}

// sealAAD ties a sealed value to its host and field, so a value copied into
// another host or field does not open
func sealAAD(hostID, field string) []byte {
	return []byte("sshr\x00" + hostID + "\x00" + field)
}

// SealFor seals plain for one destination, the address, user, port and
// jump hosts go into the associated data, a value moved to another host
// file or a host whose address was changed outside sshr does not open
func SealFor(plain []byte, hostID, field, dest string) (string, error) {
	out, err := SealRaw(plain, sealAAD(hostID, field+"\x00"+dest))
	if err != nil {
		return "", err
	}
	return SealPrefix2 + out, nil
}

// UnsealFor opens a value of SealFor for dest, and an older v1 value made
// by Seal without a destination
func UnsealFor(blob, hostID, field, dest string) ([]byte, error) {
	if raw, ok := strings.CutPrefix(blob, SealPrefix2); ok {
		return UnsealRaw(raw, sealAAD(hostID, field+"\x00"+dest))
	}
	return Unseal(blob, hostID, field)
}

// Seal encrypts plain with XChaCha20-Poly1305 under the vault key
func Seal(plain []byte, hostID, field string) (string, error) {
	out, err := SealRaw(plain, sealAAD(hostID, field))
	if err != nil {
		return "", err
	}
	return SealPrefix + out, nil
}

func SealRaw(plain, aad []byte) (string, error) {
	key, err := Key()
	if err != nil {
		return "", err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plain)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := aead.Seal(nonce, nonce, plain, aad)
	return base64.StdEncoding.EncodeToString(out), nil
}

// ErrSealBroken means a saved secret does not open with the vault key, the
// keychain was reset or the host file was copied from another machine
var ErrSealBroken = errors.New("sealed_broken")

// Unseal opens a value made by Seal
func Unseal(blob, hostID, field string) ([]byte, error) {
	raw, ok := strings.CutPrefix(blob, SealPrefix)
	if !ok {
		return nil, fmt.Errorf("%w: unknown format", ErrSealBroken)
	}
	return UnsealRaw(raw, sealAAD(hostID, field))
}

func UnsealRaw(raw string, aad []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSealBroken, err)
	}
	key, err := Key()
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(data) < aead.NonceSize() {
		return nil, fmt.Errorf("%w: too short", ErrSealBroken)
	}
	plain, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], aad)
	if err != nil {
		return nil, ErrSealBroken
	}
	return plain, nil
}

// CheckKeychain tells whether saved secrets can be used here, it creates
// the vault key if there is none yet
func CheckKeychain() error {
	_, err := Key()
	return err
}

// Keychain is where sshr keeps its own secrets: the vault key and the keys
// of the sync device, values are base64 text under a name, Get returns
// ErrSecretNotFound for a name it does not hold, the system keychain is
// the one implementation today, a passphrase file or a phone keystore can
// take its place
type Keychain interface {
	Get(name string) (string, error)
	Set(name, value string) error
	Delete(name string) error
}

// ErrSecretNotFound is what a Keychain returns for a name it does not
// hold, the code that uses a keychain does not depend on go-keyring
var ErrSecretNotFound = errors.New("secret not found in the keychain")

// stateKeychain is a Keychain that can tell a failure that means it is
// missing or locked from any other
type stateKeychain interface {
	State(err error) error
}

// keychain is the keychain every secret of sshr goes through, every call
// still runs through keyringCall for its time limit, none until a front
// end sets one with SetKeychain
var keychain Keychain = noKeychain{}

// SetKeychain sets the keychain the vault key and the named secrets go
// through, the front ends set the system keychain at start, a build that
// sets none has no keychain
func SetKeychain(k Keychain) { keychain = k }

// noKeychain is the keychain of a build that set none
type noKeychain struct{}

func (noKeychain) Get(string) (string, error) { return "", ErrKeychainMissing }
func (noKeychain) Set(string, string) error   { return ErrKeychainMissing }
func (noKeychain) Delete(string) error        { return ErrKeychainMissing }
func (noKeychain) State(error) error          { return ErrKeychainMissing }

// ResetForTest forgets the cached vault key, a pending store and the quiet
// minute and puts the vault lock and its files under the folder of
// lockPath, tests of other packages start from a clean vault with it,
// sshr itself never calls it
func ResetForTest(lockPath string) {
	vaultMu.Lock()
	vaultKey = nil
	keySetPending = false
	tokenFailedAt = time.Time{}
	pinHold = false
	stopIdle()
	vaultMu.Unlock()
	keyringMu.Lock()
	keyringDownUntil = time.Time{}
	keyringMu.Unlock()
	vaultLockPath = func() (string, error) { return lockPath, nil }
}

// SecretGet reads a value sshr keeps in the system keychain, ok is false
// when there is none
func SecretGet(name string) (value []byte, ok bool, err error) {
	v, err := callStore(secretStore(name), func(k Keychain) (string, error) { return k.Get(name) })
	if errors.Is(err, ErrSecretNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, false, keychainError(fmt.Errorf("the keychain entry %s is damaged", name))
	}
	return b, true, nil
}

// SecretSet stores a value in the system keychain, or in the passphrase
// vault file when the vault is under a passphrase
func SecretSet(name string, value []byte) error {
	enc := base64.StdEncoding.EncodeToString(value)
	_, err := callStore(secretStore(name), func(k Keychain) (string, error) { return "", k.Set(name, enc) })
	return err
}

// SecretDelete removes a value, a missing one is not an error
func SecretDelete(name string) error {
	_, err := callStore(secretStore(name), func(k Keychain) (string, error) { return "", k.Delete(name) })
	if err != nil && !errors.Is(err, ErrSecretNotFound) {
		return err
	}
	return nil
}

// callStore runs f on k, the system keychain under the time limit and its
// error states, the passphrase vault file directly, its passphrase prompt
// must not run into the keychain time limit
func callStore(k Keychain, f func(Keychain) (string, error)) (string, error) {
	if _, ok := k.(fileKeychain); ok {
		return f(k)
	}
	v, err := keyringCall(func() (string, error) { return f(k) })
	if err != nil && !errors.Is(err, ErrSecretNotFound) {
		return "", keychainError(err)
	}
	return v, err
}
