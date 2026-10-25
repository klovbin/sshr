package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// SlotInfo describes a slot of vault-key.json without anything secret
type SlotInfo struct {
	ID     string
	Type   string
	Label  string
	UV     bool
	Legacy bool
	// whole tells the slot has every part it needs to open
	whole bool
}

// Slots lists the slots of the vault kept in vault-key.json, a file of
// format 1 is one legacy passphrase slot
func Slots() ([]SlotInfo, error) {
	if Mode() != ModePassphrase {
		return nil, errors.New("the vault key is in the system keychain, it has no slots")
	}
	v1, f, err := readKeyFile()
	if err != nil {
		return nil, err
	}
	return slotInfos(v1, f)
}

func slotInfos(v1 *wrappedKey, f *keyFile) ([]SlotInfo, error) {
	if v1 != nil {
		return []SlotInfo{{ID: "v1", Type: slotPassphrase, Legacy: true, whole: true}}, nil
	}
	var out []SlotInfo
	for _, raw := range f.Slots {
		var s struct {
			slotHead
			Label  string `json:"label"`
			UV     bool   `json:"uv"`
			Legacy bool   `json:"legacy"`
			Salt   []byte `json:"salt"`
			Sealed []byte `json:"sealed"`
			Cred   []byte `json:"cred"`
		}
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		// a slot without its parts opens nothing and is no way in
		whole := len(s.Salt) > 0 && len(s.Sealed) > 0 && (s.Type != slotFIDO2 || len(s.Cred) > 0 && len(s.Salt) == tokenSecretLen)
		out = append(out, SlotInfo{ID: s.ID, Type: s.Type, Label: terminalText(s.Label), UV: s.UV, Legacy: s.Legacy, whole: whole})
	}
	return out, nil
}

// canRemove tells whether the slot id may go: never the last slot, never
// the last way in that is not a token unless two tokens stay, a lost token
// must leave a way back
func canRemove(slots []SlotInfo, id string) error {
	var gone *SlotInfo
	tokens, typed := 0, 0
	for i := range slots {
		if slots[i].ID == id {
			gone = &slots[i]
			continue
		}
		switch {
		case !slots[i].whole:
		case slots[i].Type == slotFIDO2:
			tokens++
		case slots[i].Type == slotPassphrase || slots[i].Type == slotRecovery:
			typed++
		}
	}
	switch {
	case gone == nil:
		return fmt.Errorf("the vault has no slot %s, sshr vault slots lists them", id)
	case tokens+typed == 0:
		return errors.New("that is the last way into the vault, add another before removing it")
	case typed == 0 && tokens < 2:
		return errors.New("without it only one token opens the vault and a lost token loses every secret, keep a passphrase or a recovery code, or add a second token first")
	}
	return nil
}

// RemoveSlot removes the slot id from vault-key.json, the vault must open
// first, any slot opens it, the other slots are written back as they were
func RemoveSlot(id string) error {
	slots, err := Slots()
	if err != nil {
		return err
	}
	if err := canRemove(slots, id); err != nil {
		return err
	}
	if _, err := Key(); err != nil {
		return err
	}
	unlock, err := vaultModeLock()
	if err != nil {
		return err
	}
	defer unlock()
	path, err := passphraseFilePath()
	if err != nil {
		return err
	}
	old, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// the file is read again under the lock, the rules are checked on the
	// bytes that are edited
	v1, f, err := parseKeyFile(old)
	if err != nil {
		return err
	}
	now, err := slotInfos(v1, f)
	if err != nil {
		return err
	}
	if err := canRemove(now, id); err != nil {
		return err
	}
	if f == nil {
		return errors.New("a vault key file of format 1 has one slot only")
	}
	var kept []json.RawMessage
	for _, raw := range f.Slots {
		var h slotHead
		if json.Unmarshal(raw, &h) == nil && h.ID != id {
			kept = append(kept, raw)
		}
	}
	b, err := marshalKeyFile(keyFile{Version: keyFileVersion, Slots: kept})
	if err != nil {
		return err
	}
	if err := writeKeyFile(path, b); err != nil {
		return err
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, b) {
		if rerr := writeKeyFile(path, old); rerr != nil {
			return fmt.Errorf("%s did not read back after the slot was removed and the old file could not be put back: %v, %v", path, err, rerr)
		}
		return fmt.Errorf("%s did not read back after the slot was removed, it is put back as it was: %v", path, err)
	}
	slotsChanged()
	return nil
}
