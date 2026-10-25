package vault

import (
	"bytes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"

	"sshr.dev/internal/fileio"
	"sshr.dev/internal/handcode"
)

// The recovery code opens the vault when the token or the passphrase is
// gone: 128 random bits written with handcode, shown once, offline
// guessing gets nowhere, so no Argon2 is needed, the key that wraps the
// vault key is HKDF of the code, salted per slot, a code that opened the
// vault is replaced by a new one, by sshr itself on a terminal

const (
	slotRecovery = "recovery"
	// recoverySecretLen is the random part of a recovery code
	recoverySecretLen = 16
)

// ErrBadRecoveryCode means the code is a recovery code and opens no slot
var ErrBadRecoveryCode = errors.New("bad_recovery_code")

// recoverySlot wraps the key with HKDF of a recovery code
type recoverySlot struct {
	slotHead
	Salt   []byte `json:"salt"`
	Sealed []byte `json:"sealed"`
}

// recoveryUsed is set when a recovery code opened the vault in this run
var recoveryUsed atomic.Bool

// RecoveryUsed tells whether a recovery code opened the vault in this run,
// the code should be replaced, it was typed somewhere
func RecoveryUsed() bool { return recoveryUsed.Load() }

func recoveryAEAD(secret, salt []byte, id string) (cipher.AEAD, error) {
	k, err := hkdf.Key(sha256.New, secret, salt, "sshr/vault/recovery/v2\x00"+id, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.NewX(k)
}

// newRecoverySlot wraps key under a new recovery code, the code comes back
// as the text to show
func newRecoverySlot(key []byte, taken map[string]bool) (code string, slot json.RawMessage, err error) {
	secret := make([]byte, recoverySecretLen)
	if _, err := rand.Read(secret); err != nil {
		return "", nil, err
	}
	var id string
	for id == "" || taken[id] {
		if id, err = newSlotID(); err != nil {
			return "", nil, err
		}
	}
	s := recoverySlot{slotHead: slotHead{ID: id, Type: slotRecovery}, Salt: make([]byte, 32)}
	if _, err := rand.Read(s.Salt); err != nil {
		return "", nil, err
	}
	aead, err := recoveryAEAD(secret, s.Salt, id)
	if err != nil {
		return "", nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, err
	}
	s.Sealed = aead.Seal(nonce, nonce, key, slotAAD(slotRecovery, id))
	b, err := json.Marshal(s)
	if err != nil {
		return "", nil, err
	}
	return handcode.Encode(secret), b, nil
}

// recoverySecret is the random part of text when text is a recovery code,
// a typo in it is an error that names its group
func recoverySecret(text string) ([]byte, error) {
	b, err := handcode.Decode(text)
	if err != nil {
		return nil, fmt.Errorf("recovery code: %w", err)
	}
	if len(b) != recoverySecretLen {
		return nil, errors.New("recovery code: it is not as long as a recovery code")
	}
	return b, nil
}

// looksLikeRecoveryCode tells a recovery code from a passphrase, a code
// passes the check of its groups and of the whole, a passphrase does not
func looksLikeRecoveryCode(text string) bool {
	_, err := recoverySecret(text)
	return err == nil
}

// recoveryCodeGroups is how many groups a recovery code has, its 16 bytes
// and the check of the whole make 32 characters
const recoveryCodeGroups = 8

// recoveryTypo is the error of text that has the shape of a recovery code
// and does not pass its checks, nil for anything else, it names a group
// and never a character
func recoveryTypo(text string) error {
	if !handcode.Shaped(text, recoveryCodeGroups) {
		return nil
	}
	_, err := recoverySecret(text)
	return err
}

// openRecoverySlots opens the key with the recovery code text
func openRecoverySlots(f *keyFile, text string) ([]byte, error) {
	secret, err := recoverySecret(text)
	if err != nil {
		return nil, err
	}
	slots, err := slotsOf[recoverySlot](f, slotRecovery)
	if err != nil {
		return nil, err
	}
	for _, s := range slots {
		aead, err := recoveryAEAD(secret, s.Salt, s.ID)
		if err != nil {
			return nil, err
		}
		if len(s.Sealed) < aead.NonceSize() {
			continue
		}
		key, err := aead.Open(nil, s.Sealed[:aead.NonceSize()], s.Sealed[aead.NonceSize():], slotAAD(slotRecovery, s.ID))
		if err == nil && len(key) == chacha20poly1305.KeySize {
			return key, nil
		}
	}
	return nil, ErrBadRecoveryCode
}

// hasSlot tells whether f holds a slot of kind typ
func hasSlot(f *keyFile, typ string) bool {
	if f == nil {
		return false
	}
	for _, raw := range f.Slots {
		var h slotHead
		if json.Unmarshal(raw, &h) == nil && h.Type == typ {
			return true
		}
	}
	return false
}

// withRecovery returns the file old with its recovery slots replaced by a
// new one for key, a file of format 1 becomes format 2 with its passphrase
// wrap kept as a legacy slot, the passphrase is not needed for that
func withRecovery(old []byte, key []byte) (code string, out []byte, err error) {
	v1, f, err := parseKeyFile(old)
	if err != nil {
		return "", nil, err
	}
	var kept []json.RawMessage
	taken := map[string]bool{}
	if f != nil && len(f.Slots) >= keySlotsMax && !hasSlot(f, slotRecovery) {
		return "", nil, fmt.Errorf("the vault key file holds %d slots, no more fit", len(f.Slots))
	}
	if v1 != nil {
		slot, err := json.Marshal(passphraseSlot{slotHead: slotHead{ID: "v1", Type: slotPassphrase}, wrappedKey: *v1, Legacy: true})
		if err != nil {
			return "", nil, err
		}
		kept, taken["v1"] = append(kept, slot), true
	} else {
		for _, raw := range f.Slots {
			var h slotHead
			if json.Unmarshal(raw, &h) == nil && h.Type != slotRecovery {
				kept, taken[h.ID] = append(kept, raw), true
			}
		}
	}
	code, slot, err := newRecoverySlot(key, taken)
	if err != nil {
		return "", nil, err
	}
	out, err = marshalKeyFile(keyFile{Version: keyFileVersion, Slots: append(kept, slot)})
	return code, out, err
}

// NewRecoveryCode replaces the recovery code of the passphrase vault,
// confirm shows the code and gets a part of it back, an error from confirm
// changes nothing, the file is written under the mode lock only if no
// other process changed it while the code was shown, and only kept when
// it opens with the new code and keeps the passphrase slot as it was
func NewRecoveryCode(confirm func(code string) error) error {
	if Mode() != ModePassphrase {
		return errors.New("a recovery code is for a vault kept in vault-key.json, run sshr vault passphrase first")
	}
	key, err := Key()
	if err != nil {
		return err
	}
	path, err := passphraseFilePath()
	if err != nil {
		return err
	}
	old, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	v1, _, err := parseKeyFile(old)
	if err != nil {
		return err
	}
	code, b, err := withRecovery(old, key)
	if err != nil {
		return err
	}
	// a person may take minutes over the code, the lock waits for that
	if err := confirm(code); err != nil {
		return err
	}
	unlock, err := vaultModeLock()
	if err != nil {
		return err
	}
	defer unlock()
	now, err := os.ReadFile(path)
	if err != nil || Mode() != ModePassphrase || !bytes.Equal(now, old) {
		return errors.New("the vault changed while the code was shown, nothing is saved, run sshr vault recovery again")
	}
	check := func(f *keyFile) ([]byte, error) {
		if err := legacyKept(f, v1); err != nil {
			return nil, err
		}
		return openRecoverySlots(f, code)
	}
	if err := writeKeyFileChecked(path, old, b, check, key); err != nil {
		return err
	}
	recoveryUsed.Store(false)
	return nil
}

// legacyKept checks that a file of format 1 moved into format 2 kept its
// passphrase wrap as it was, the passphrase is not at hand to try it
func legacyKept(f *keyFile, v1 *wrappedKey) error {
	if v1 == nil {
		return nil
	}
	slots, err := slotsOf[passphraseSlot](f, slotPassphrase)
	if err != nil {
		return err
	}
	for _, s := range slots {
		w := s.wrappedKey
		if s.Legacy && w.Version == v1.Version && w.KDF == v1.KDF && w.Time == v1.Time && w.MemoryKiB == v1.MemoryKiB &&
			w.Threads == v1.Threads && bytes.Equal(w.Salt, v1.Salt) && bytes.Equal(w.Sealed, v1.Sealed) {
			return nil
		}
	}
	return errors.New("the passphrase wrap did not survive the move into format 2")
}

func writeKeyFile(path string, b []byte) error { return fileio.WriteFile(path, b, 0o600) }

// writeKeyFileChecked writes b to path, reads it back and opens it with
// open, a file that does not give key back is replaced by old
func writeKeyFileChecked(path string, old, b []byte, open func(*keyFile) ([]byte, error), key []byte) error {
	if err := writeKeyFile(path, b); err != nil {
		return err
	}
	_, f, err := readKeyFile()
	if err == nil {
		var got []byte
		if got, err = open(f); err == nil && !bytes.Equal(got, key) {
			err = errors.New("another key")
		}
	}
	if err == nil {
		return nil
	}
	if rerr := writeKeyFile(path, old); rerr != nil {
		return fmt.Errorf("%s does not give the vault key back after the write and the old file could not be put back, the passphrase still opens it: %v, %v", path, err, rerr)
	}
	return fmt.Errorf("%s does not give the vault key back after the write, it is put back as it was: %v", path, err)
}
