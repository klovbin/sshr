package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// cheapArgon makes Argon2 fast for a test
func cheapArgon(t *testing.T) {
	t.Helper()
	old := argonParams
	argonParams.Time, argonParams.MemoryKiB, argonParams.Threads = 1, 8, 1
	t.Cleanup(func() { argonParams = old })
}

// a file of format 1 stays format 1 when its passphrase changes, the
// format an older sshr reads
func TestPassphraseKeepsFormatOne(t *testing.T) {
	cheapArgon(t)
	key := bytes.Repeat([]byte{7}, 32)
	b, err := withPassphrase(nil, key, "first passphrase")
	if err != nil {
		t.Fatal(err)
	}
	b, err = withPassphrase(b, key, "second passphrase")
	if err != nil {
		t.Fatal(err)
	}
	v1, kf, err := parseKeyFile(b)
	if err != nil || v1 == nil || kf != nil {
		t.Fatalf("not format 1: %v %s", err, b)
	}
	if got, err := openPassphraseSlots(v1, kf, "second passphrase"); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("the new passphrase: %v", err)
	}
}

// a file of format 2 opens with its passphrase slot, a new passphrase
// replaces that slot and keeps a slot of a kind this sshr does not know
func TestPassphraseSlotKeepsOtherSlots(t *testing.T) {
	cheapArgon(t)
	key := bytes.Repeat([]byte{9}, 32)
	w, err := wrapKeyAAD(key, "first passphrase", slotAAD(slotPassphrase, "p1"))
	if err != nil {
		t.Fatal(err)
	}
	pslot, _ := json.Marshal(passphraseSlot{slotHead: slotHead{ID: "p1", Type: slotPassphrase}, wrappedKey: *w})
	other := json.RawMessage(`{"id":"s9","type":"server","url":"https://example.org","sealed":"AAAA"}`)
	b, _ := json.Marshal(keyFile{Version: keyFileVersion, Slots: []json.RawMessage{pslot, other}})

	v1, kf, err := parseKeyFile(b)
	if err != nil || v1 != nil || len(kf.Slots) != 2 {
		t.Fatalf("parse: %v", err)
	}
	if got, err := openPassphraseSlots(v1, kf, "first passphrase"); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("open: %v", err)
	}
	if _, err := openPassphraseSlots(v1, kf, "wrong passphrase"); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("a wrong passphrase: %v", err)
	}

	b, err = withPassphrase(b, key, "second passphrase")
	if err != nil {
		t.Fatal(err)
	}
	_, kf, err = parseKeyFile(b)
	if err != nil || kf == nil || len(kf.Slots) != 2 {
		t.Fatalf("after the change: %v %s", err, b)
	}
	var compact bytes.Buffer
	json.Compact(&compact, b)
	if !strings.Contains(compact.String(), `{"id":"s9","type":"server","url":"https://example.org","sealed":"AAAA"}`) {
		t.Errorf("the server slot was lost: %s", b)
	}
	if _, err := openPassphraseSlots(nil, kf, "first passphrase"); !errors.Is(err, ErrBadPassphrase) {
		t.Errorf("the old passphrase still opens: %v", err)
	}
	if got, err := openPassphraseSlots(nil, kf, "second passphrase"); err != nil || !bytes.Equal(got, key) {
		t.Errorf("the new passphrase: %v", err)
	}
}

// a wrap moved to another slot ID opens nothing
func TestSlotWrapIsBoundToItsSlot(t *testing.T) {
	cheapArgon(t)
	key := bytes.Repeat([]byte{3}, 32)
	w, _ := wrapKeyAAD(key, "a passphrase", slotAAD(slotPassphrase, "p1"))
	moved, _ := json.Marshal(passphraseSlot{slotHead: slotHead{ID: "p2", Type: slotPassphrase}, wrappedKey: *w})
	b, _ := json.Marshal(keyFile{Version: keyFileVersion, Slots: []json.RawMessage{moved}})
	_, kf, err := parseKeyFile(b)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := openPassphraseSlots(nil, kf, "a passphrase"); err == nil {
		t.Fatalf("a moved wrap gave %x", got)
	}
}

// files that are not a vault key file of a known shape are refused, a
// file without a passphrase slot says so when a passphrase opens it
func TestParseKeyFileRefuses(t *testing.T) {
	slot := `{"id":"a","type":"passphrase"}`
	many := strings.TrimSuffix(strings.Repeat(`{"id":"x","type":"t"},`, keySlotsMax+1), ",")
	for name, b := range map[string]string{
		"format 3":   `{"version":3,"slots":[` + slot + `]}`,
		"no slots":   `{"version":2,"slots":[]}`,
		"same ID":    `{"version":2,"slots":[` + slot + `,` + slot + `]}`,
		"no kind":    `{"version":2,"slots":[{"id":"a"}]}`,
		"many slots": `{"version":2,"slots":[` + many + `]}`,
		"not json":   `{"version":2,`,
	} {
		if _, _, err := parseKeyFile([]byte(b)); err == nil {
			t.Errorf("%s was taken", name)
		}
	}
	v1, kf, err := parseKeyFile([]byte(`{"version":2,"slots":[{"id":"b","type":"server"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openPassphraseSlots(v1, kf, "x"); err == nil || !strings.Contains(err.Error(), "no passphrase slot") {
		t.Errorf("a file without a passphrase slot: %v", err)
	}
}

// a damaged passphrase slot does not hide the good one after it
func TestDamagedPassphraseSlotIsSkipped(t *testing.T) {
	cheapArgon(t)
	key := bytes.Repeat([]byte{5}, 32)
	w, _ := wrapKeyAAD(key, "a passphrase", slotAAD(slotPassphrase, "good"))
	bad, _ := json.Marshal(passphraseSlot{slotHead: slotHead{ID: "bad", Type: slotPassphrase}, wrappedKey: wrappedKey{Version: 1, KDF: "argon2id", Time: 99}})
	good, _ := json.Marshal(passphraseSlot{slotHead: slotHead{ID: "good", Type: slotPassphrase}, wrappedKey: *w})
	b, _ := json.Marshal(keyFile{Version: keyFileVersion, Slots: []json.RawMessage{bad, good}})
	_, kf, err := parseKeyFile(b)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := openPassphraseSlots(nil, kf, "a passphrase"); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("the good slot after a damaged one: %v", err)
	}
}
