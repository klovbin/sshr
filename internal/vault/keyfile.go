package vault

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// vault-key.json of format 2 holds slots, each wraps the same vault key in
// its own way, any one opens the vault, a passphrase now, a hardware token
// and a recovery code next, a server or a password manager may follow, a
// file of format 1 is one passphrase wrap and stays format 1 until a slot
// of another kind is added, an older sshr refuses format 2 by its version
// before it uses anything in it, a slot of a kind this sshr does not know
// is written back as it was read

const (
	keyFileVersion = 2
	slotPassphrase = "passphrase"
	// keyFileMax is more than a few slots ever need, a credential ID of a
	// token may take 1023 bytes
	keyFileMax = 64 << 10
	// keySlotsMax keeps a crafted file from making sshr try slots forever
	keySlotsMax = 16
	// passphraseSlotsMax is how many passphrase slots an open tries, each
	// costs an Argon2 run
	passphraseSlotsMax = 2
)

// keyFile is vault-key.json of format 2
type keyFile struct {
	Version int               `json:"version"`
	Slots   []json.RawMessage `json:"slots"`
}

// slotHead is what every slot has
type slotHead struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// passphraseSlot wraps the key with Argon2id of a passphrase, the wrap is
// the one of format 1, bound to the kind and the ID of its slot, a legacy
// slot is the wrap of a file of format 1 moved as it was into format 2,
// bound as format 1 binds, the next passphrase change binds it to its slot
type passphraseSlot struct {
	slotHead
	wrappedKey
	Legacy bool `json:"legacy,omitempty"`
}

func (s *passphraseSlot) aad() []byte {
	if s.Legacy {
		return wrapAAD
	}
	return slotAAD(slotPassphrase, s.ID)
}

// slotAAD binds a wrap to its slot, a wrap moved to another slot or a slot
// whose kind or ID was changed fails as damaged instead of giving a key
func slotAAD(typ, id string) []byte {
	return []byte("sshr/vault-key/v2\x00" + typ + "\x00" + id)
}

// newSlotID is a short random name for a slot, unique in its file
func newSlotID() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// parseKeyFile reads vault-key.json, a file of format 1 comes back as v1
// and kf nil, a file of format 2 as kf, its slots are checked for a kind
// and an ID only, each kind checks the rest when it opens its slot
func parseKeyFile(b []byte) (v1 *wrappedKey, kf *keyFile, err error) {
	var head struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return nil, nil, err
	}
	switch head.Version {
	case 1:
		var w wrappedKey
		if err := json.Unmarshal(b, &w); err != nil {
			return nil, nil, err
		}
		return &w, nil, nil
	case keyFileVersion:
	default:
		return nil, nil, fmt.Errorf("format %d, this sshr reads formats 1 and %d", head.Version, keyFileVersion)
	}
	var f keyFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, nil, err
	}
	if len(f.Slots) == 0 || len(f.Slots) > keySlotsMax {
		return nil, nil, fmt.Errorf("%d slots, a vault key file has 1 to %d", len(f.Slots), keySlotsMax)
	}
	ids := map[string]bool{}
	for _, raw := range f.Slots {
		var h slotHead
		if err := json.Unmarshal(raw, &h); err != nil {
			return nil, nil, err
		}
		if h.ID == "" || h.Type == "" || ids[h.ID] {
			return nil, nil, errors.New("a slot without a kind, without an ID or with the ID of another slot")
		}
		ids[h.ID] = true
	}
	return nil, &f, nil
}

// slotsOf returns the slots of kind typ, decoded into values of T
func slotsOf[T any](f *keyFile, typ string) ([]T, error) {
	var out []T
	for _, raw := range f.Slots {
		var h slotHead
		if err := json.Unmarshal(raw, &h); err != nil {
			return nil, err
		}
		if h.Type != typ {
			continue
		}
		var s T
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("the %s slot %s is damaged: %v", typ, h.ID, err)
		}
		out = append(out, s)
	}
	return out, nil
}

// openPassphraseSlots opens the key with pass from a file of either
// format, a wrong passphrase is ErrBadPassphrase, a file of format 2
// without a passphrase slot says so
func openPassphraseSlots(v1 *wrappedKey, f *keyFile, pass string) ([]byte, error) {
	if v1 != nil {
		return unwrapKey(v1, pass)
	}
	slots, err := slotsOf[passphraseSlot](f, slotPassphrase)
	if err != nil {
		return nil, err
	}
	if len(slots) == 0 {
		return nil, errors.New("the vault key file has no passphrase slot")
	}
	// sshr writes one passphrase slot, a crafted file with more would make
	// every open pay Argon2 for each, a damaged slot does not hide the next
	var last error = ErrBadPassphrase
	for _, s := range slots[:min(len(slots), passphraseSlotsMax)] {
		key, err := unwrapKeyAAD(&s.wrappedKey, pass, s.aad())
		if err == nil {
			return key, nil
		}
		if !errors.Is(err, ErrBadPassphrase) {
			last = err
		}
	}
	return nil, last
}

// withPassphrase returns the file old with its passphrase wrap replaced by
// a wrap of key under pass, a file of format 2 keeps its other slots as
// they are and gets one passphrase slot, any other file becomes format 1,
// the format an older sshr still reads
func withPassphrase(old []byte, key []byte, pass string) ([]byte, error) {
	var f *keyFile
	if len(old) > 0 {
		if _, kf, err := parseKeyFile(old); err == nil {
			f = kf
		}
	}
	if f == nil {
		w, err := wrapKey(key, pass)
		if err != nil {
			return nil, err
		}
		return marshalKeyFile(w)
	}
	taken := map[string]bool{}
	for _, raw := range f.Slots {
		var h slotHead
		if json.Unmarshal(raw, &h) == nil && h.Type != slotPassphrase {
			taken[h.ID] = true
		}
	}
	var id string
	for id == "" || taken[id] {
		var err error
		if id, err = newSlotID(); err != nil {
			return nil, err
		}
	}
	w, err := wrapKeyAAD(key, pass, slotAAD(slotPassphrase, id))
	if err != nil {
		return nil, err
	}
	slot, err := json.Marshal(passphraseSlot{slotHead: slotHead{ID: id, Type: slotPassphrase}, wrappedKey: *w})
	if err != nil {
		return nil, err
	}
	out := keyFile{Version: keyFileVersion, Slots: []json.RawMessage{slot}}
	for _, raw := range f.Slots {
		var h slotHead
		if json.Unmarshal(raw, &h) == nil && h.Type != slotPassphrase {
			out.Slots = append(out.Slots, raw)
		}
	}
	return marshalKeyFile(out)
}

func marshalKeyFile(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
