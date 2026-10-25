package vault

import (
	"bytes"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/chacha20poly1305"
)

// A token slot wraps the vault key with the hmac-secret of a credential on
// a FIDO2 token: the token answers a salt with an HMAC only it can make,
// so a copy of vault-key.json opens nothing without the token in hand, the
// package runs no program, the front end sets how the token is asked

const (
	slotFIDO2 = "fido2"
	// tokenRP names the credentials of the vault on a token, apart from the
	// ssh: ones of OpenSSH
	tokenRP = "sshr:vault"
	// tokenSecretLen is the length of an hmac-secret and of its salt
	tokenSecretLen = 32
)

// ErrNoToken means no token answered: the program that asks it is not
// installed, no token is plugged in, or none holds the credential, the
// vault is then opened another way
var ErrNoToken = errors.New("no_token")

// fido2Slot wraps the key with HKDF of the hmac-secret the token gives for
// Salt, Cred names the credential, UV is fixed at enrolment, a token gives
// another secret with user verification than without
type fido2Slot struct {
	slotHead
	RP     string `json:"rp"`
	Cred   []byte `json:"cred"`
	UV     bool   `json:"uv"`
	Label  string `json:"label,omitempty"`
	Salt   []byte `json:"salt"`
	Sealed []byte `json:"sealed"`
}

// TokenRequest is one question to a token: the credential, the salt and
// whether user verification is asked
type TokenRequest struct {
	RP    string
	Cred  []byte
	Salt  []byte
	UV    bool
	Label string
}

// TokenEnrolment makes a credential with hmac-secret on a token and gives
// its ID and the secret it answers for salt, known are the credentials the
// vault has, a token that holds one of them is enrolled already and must
// be refused, two slots on one key would pass for two keys
type TokenEnrolment func(rp string, salt []byte, uv bool, known [][]byte) (cred, secret []byte, err error)

// askToken gets the hmac-secret of a credential, nil when the front end
// set none, the vault then opens another way
var askToken func(TokenRequest) ([]byte, error)

// SetToken sets how a token is asked for its hmac-secret, the front ends
// run the FIDO2 tools for it
func SetToken(ask func(TokenRequest) ([]byte, error)) { askToken = ask }

// aad binds the wrap to its slot and to what the token is asked, a slot
// whose credential, relying party or user verification was edited fails
// as damaged instead of asking the token another question
func (s *fido2Slot) aad() []byte {
	sum := sha256.Sum256(s.Cred)
	return append(slotAAD(slotFIDO2, s.ID), []byte("\x00"+s.RP+"\x00"+hex.EncodeToString(sum[:])+"\x00"+strconv.FormatBool(s.UV))...)
}

func tokenWrapKey(secret []byte, id string) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, nil, "sshr/vault/fido2/v2\x00"+id, chacha20poly1305.KeySize)
}

// newFIDO2Slot enrols a credential and wraps key with its secret
func newFIDO2Slot(key []byte, enrol TokenEnrolment, uv bool, label string, taken map[string]bool, known [][]byte) (json.RawMessage, error) {
	s := fido2Slot{RP: tokenRP, UV: uv, Label: label, Salt: make([]byte, tokenSecretLen)}
	var err error
	for s.ID == "" || taken[s.ID] {
		if s.ID, err = newSlotID(); err != nil {
			return nil, err
		}
	}
	s.Type = slotFIDO2
	if _, err := rand.Read(s.Salt); err != nil {
		return nil, err
	}
	cred, secret, err := enrol(s.RP, s.Salt, uv, known)
	if err != nil {
		return nil, err
	}
	if len(cred) == 0 || len(secret) != tokenSecretLen {
		return nil, errors.New("the token gave no credential or a secret of the wrong length")
	}
	s.Cred = cred
	k, err := tokenWrapKey(secret, s.ID)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	s.Sealed = aead.Seal(nonce, nonce, key, s.aad())
	return json.Marshal(s)
}

// tokenCooldown is how long a process does not ask a token again after a
// question got no answer, a server that needs the vault on every call
// would otherwise wait for a touch each time and blink the key on and on
const tokenCooldown = 2 * time.Minute

// tokenFailedAt is when a token question last got no answer, vaultMu
var tokenFailedAt time.Time

// openTokenSlots asks the token for each token slot in turn, ErrNoToken
// when none answered, an answer that opens nothing is an error of its own,
// after a question without an answer the token is left alone a while
func openTokenSlots(f *keyFile) ([]byte, error) {
	if askToken == nil {
		return nil, fmt.Errorf("%w: this build cannot ask a token", ErrNoToken)
	}
	if !tokenFailedAt.IsZero() && time.Since(tokenFailedAt) < tokenCooldown {
		return nil, fmt.Errorf("%w: the security key gave no answer a moment ago, it is asked again in %s", ErrNoToken, tokenCooldown)
	}
	key, err := askTokenSlots(f)
	if errors.Is(err, ErrNoToken) {
		tokenFailedAt = time.Now()
	} else if err == nil {
		tokenFailedAt = time.Time{}
	}
	return key, err
}

func askTokenSlots(f *keyFile) ([]byte, error) {
	slots, err := slotsOf[fido2Slot](f, slotFIDO2)
	if err != nil {
		return nil, err
	}
	var last error = ErrNoToken
	for _, s := range slots {
		if len(s.Salt) != tokenSecretLen || len(s.Cred) == 0 {
			last = fmt.Errorf("the token slot %s is damaged", s.ID)
			continue
		}
		secret, err := askToken(TokenRequest{RP: s.RP, Cred: s.Cred, Salt: s.Salt, UV: s.UV, Label: s.Label})
		if err != nil {
			last = err
			continue
		}
		if len(secret) != tokenSecretLen {
			last = errors.New("the token gave a secret of the wrong length")
			continue
		}
		k, err := tokenWrapKey(secret, s.ID)
		if err != nil {
			return nil, err
		}
		aead, err := chacha20poly1305.NewX(k)
		if err != nil {
			return nil, err
		}
		if len(s.Sealed) < aead.NonceSize() {
			last = fmt.Errorf("the token slot %s is damaged", s.ID)
			continue
		}
		key, err := aead.Open(nil, s.Sealed[:aead.NonceSize()], s.Sealed[aead.NonceSize():], s.aad())
		if err != nil || len(key) != chacha20poly1305.KeySize {
			last = fmt.Errorf("the token %s answered, but its answer opens no vault key, another token or another user verification setting than at enrolment", terminalText(s.Label))
			continue
		}
		return key, nil
	}
	return nil, last
}

// AddToken adds a slot for a key on a FIDO2 token to the vault kept in
// vault-key.json: enrol makes the credential and gives its first answer,
// the first token also gets a recovery code, confirm shows it and gets a
// part of it back, the file is written under the mode lock only if no
// other process changed it meanwhile, and kept only when the token opens
// it again and the other slots are as they were
func AddToken(enrol TokenEnrolment, uv bool, label string, confirm func(code string) error) error {
	if Mode() != ModePassphrase {
		return errors.New("a token slot is for a vault kept in vault-key.json, run sshr vault passphrase first")
	}
	if askToken == nil {
		return fmt.Errorf("%w: this build cannot ask a token", ErrNoToken)
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
	_, f, err := parseKeyFile(old)
	if err != nil {
		return err
	}
	needCode := !hasSlot(f, slotRecovery)
	room := 1
	if needCode {
		room = 2
	}
	kept, taken, v1, err := editableSlots(old, "", room)
	if err != nil {
		return err
	}
	var known [][]byte
	if f != nil {
		slots, err := slotsOf[fido2Slot](f, slotFIDO2)
		if err != nil {
			return err
		}
		for _, s := range slots {
			known = append(known, s.Cred)
		}
	}
	slot, err := newFIDO2Slot(key, enrol, uv, label, taken, known)
	if err != nil {
		return err
	}
	var h slotHead
	json.Unmarshal(slot, &h)
	taken[h.ID] = true
	kept = append(kept, slot)
	var code string
	if needCode {
		var rslot json.RawMessage
		if code, rslot, err = newRecoverySlot(key, taken); err != nil {
			return err
		}
		kept = append(kept, rslot)
		if err := confirm(code); err != nil {
			return err
		}
	}
	b, err := marshalKeyFile(keyFile{Version: keyFileVersion, Slots: kept})
	if err != nil {
		return err
	}
	unlock, err := vaultModeLock()
	if err != nil {
		return err
	}
	defer unlock()
	if now, err := os.ReadFile(path); err != nil || Mode() != ModePassphrase || !bytes.Equal(now, old) {
		return errors.New("the vault changed while the token was enrolled, nothing is saved, run the command again")
	}
	check := func(f *keyFile) ([]byte, error) {
		if err := legacyKept(f, v1); err != nil {
			return nil, err
		}
		if needCode {
			if _, err := openRecoverySlots(f, code); err != nil {
				return nil, err
			}
		}
		// the token is asked once more, an answer that changes from one
		// touch to the next must not lock the vault
		var written []json.RawMessage
		for _, raw := range f.Slots {
			var x slotHead
			if json.Unmarshal(raw, &x) == nil && x.ID == h.ID {
				written = append(written, raw)
			}
		}
		if len(written) == 0 {
			return nil, errors.New("the token slot is missing from the written file")
		}
		// asked past the pause, the person is at the key right now
		return askTokenSlots(&keyFile{Version: keyFileVersion, Slots: written})
	}
	return writeKeyFileChecked(path, old, b, check, key)
}

// terminalText puts ? for control characters, a label read from the file
// goes to a terminal
func terminalText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Bidi_Control) {
			return '?'
		}
		return r
	}, s)
}
