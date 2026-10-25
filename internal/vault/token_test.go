package vault

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"sshr.dev/internal/settings"
)

// fakeToken stands for a FIDO2 token: its answer is an HMAC under a secret
// of the device over the credential, the salt and the user verification
// flag, as a real token answers another secret with verification
type fakeToken struct {
	device  []byte
	present bool
	asked   int
	known   [][]byte
}

func (f *fakeToken) answer(cred, salt []byte, uv bool) []byte {
	m := hmac.New(sha256.New, f.device)
	m.Write(cred)
	m.Write(salt)
	if uv {
		m.Write([]byte{1})
	}
	return m.Sum(nil)
}

func (f *fakeToken) enrol(rp string, salt []byte, uv bool, known [][]byte) ([]byte, []byte, error) {
	f.known = known
	if !f.present {
		return nil, nil, ErrNoToken
	}
	cred := make([]byte, 64)
	rand.Read(cred)
	return cred, f.answer(cred, salt, uv), nil
}

func (f *fakeToken) ask(r TokenRequest) ([]byte, error) {
	f.asked++
	if !f.present {
		return nil, ErrNoToken
	}
	return f.answer(r.Cred, r.Salt, r.UV), nil
}

// useFakeToken plugs a fake token in for the test
func useFakeToken(t *testing.T) *fakeToken {
	t.Helper()
	f := &fakeToken{device: bytes.Repeat([]byte{0x42}, 32), present: true}
	old := askToken
	SetToken(f.ask)
	tokenFailedAt = time.Time{}
	t.Cleanup(func() { askToken, tokenFailedAt = old, time.Time{} })
	return f
}

// the first token brings a recovery code, then the vault opens with the
// token and no question, without the token the passphrase opens it
func TestTokenOpensTheVault(t *testing.T) {
	answer := "correct horse battery"
	key := passphraseVault(t, &answer)
	tok := useFakeToken(t)
	var code string
	if err := AddToken(tok.enrol, false, "yubi", func(c string) error { code = c; return nil }); err != nil {
		t.Fatal(err)
	}
	if code == "" {
		t.Fatal("the first token came without a recovery code")
	}
	slots, err := Slots()
	if err != nil || len(slots) != 3 {
		t.Fatalf("slots %+v %v", slots, err)
	}

	forgetVaultKey()
	answer = "no prompt should come"
	if got, err := Key(); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("the token: %v", err)
	}

	tok.present = false
	forgetVaultKey()
	answer = "correct horse battery"
	if got, err := Key(); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("the passphrase without the token: %v", err)
	}

	// a second token brings no second code
	tok.present = true
	code = ""
	if err := AddToken(tok.enrol, false, "solo", func(c string) error { code = c; return nil }); err != nil || code != "" {
		t.Fatalf("a second token: %v, code %q", err, code)
	}
	// the enrolment gets the credential already there, the same key twice
	// would pass for two keys
	if len(tok.known) != 1 {
		t.Errorf("the second enrolment knew %d credentials", len(tok.known))
	}
}

// a slot whose uv was edited in the file opens nothing and the vault falls
// back to its other slots
func TestTokenAnswerThatOpensNothing(t *testing.T) {
	answer := "correct horse battery"
	key := passphraseVault(t, &answer)
	tok := useFakeToken(t)
	if err := AddToken(tok.enrol, false, "yubi", func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	path, _ := passphraseFilePath()
	b, _ := os.ReadFile(path)
	edited := bytes.Replace(b, []byte(`"uv": false`), []byte(`"uv": true`), 1)
	if bytes.Equal(edited, b) {
		t.Fatal("no uv field to edit")
	}
	os.WriteFile(path, edited, 0o600)
	forgetVaultKey()
	if got, err := Key(); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("the passphrase after an edited token slot: %v", err)
	}
	_, kf, _ := readKeyFile()
	if _, err := openTokenSlots(kf); err == nil || errors.Is(err, ErrNoToken) || !strings.Contains(err.Error(), "opens no vault key") {
		t.Errorf("an edited slot: %v", err)
	}
}

// a code that was not confirmed adds no token, the slots that may go and
// those that may not
func TestTokenSlotRules(t *testing.T) {
	answer := "correct horse battery"
	passphraseVault(t, &answer)
	tok := useFakeToken(t)
	path, _ := passphraseFilePath()
	before, _ := os.ReadFile(path)
	if err := AddToken(tok.enrol, false, "yubi", func(string) error { return errors.New("not written down") }); err == nil {
		t.Fatal("a token without a confirmed code")
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Error("the file changed without a confirmed code")
	}
	if err := AddToken(tok.enrol, false, "yubi", func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	slots, _ := Slots()
	for _, s := range slots {
		ids[s.Type] = s.ID
	}
	// token, recovery code and passphrase: the passphrase may go
	if err := RemoveSlot(ids[slotPassphrase]); err != nil {
		t.Fatalf("the passphrase next to a token and a code: %v", err)
	}
	// token and code: the code is the last typed way in and stays
	if err := RemoveSlot(ids[slotRecovery]); err == nil {
		t.Error("the recovery code went with one token left")
	}
	// the token may go, the code stays
	if err := RemoveSlot(ids[slotFIDO2]); err != nil {
		t.Errorf("the token next to a code: %v", err)
	}
	if err := RemoveSlot(ids[slotRecovery]); err == nil {
		t.Error("the last slot went")
	}
	if err := RemoveSlot("nope"); err == nil {
		t.Error("a slot that is not there")
	}
}

// a token that gave no answer is left alone a while, a server would wait
// for a touch on every call
func TestTokenCooldown(t *testing.T) {
	answer := "correct horse battery"
	passphraseVault(t, &answer)
	tok := useFakeToken(t)
	if err := AddToken(tok.enrol, false, "yubi", func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	tok.present = false
	forgetVaultKey()
	Key()
	tok.present = true
	asked := tok.asked
	forgetVaultKey()
	if _, err := Key(); err != nil {
		t.Fatal(err)
	}
	if tok.asked != asked {
		t.Error("the token was asked again right after it gave no answer")
	}
}

// a slot without its parts is no way in, the rule on the last way in
// counts only slots that can open
func TestDamagedSlotIsNoWayIn(t *testing.T) {
	slots := []SlotInfo{
		{ID: "t", Type: slotFIDO2, whole: true},
		{ID: "r", Type: slotRecovery, whole: true},
		{ID: "dead", Type: slotPassphrase, whole: false},
	}
	if err := canRemove(slots, "r"); err == nil {
		t.Error("the recovery code went with only a damaged passphrase slot left beside one token")
	}
}

// a vault with a token slot drops its key after the idle time when one is
// set, the key can be touched again, without a set time or without a token
// the key is kept for the whole run
func TestTokenVaultIdleTime(t *testing.T) {
	answer := "correct horse battery"
	passphraseVault(t, &answer)
	t.Cleanup(func() { idleFor, idleLoaded = 0, false })
	st, _ := settings.Load()
	st.VaultIdleMinutes = 5
	settings.Save(st)
	idleFor, idleLoaded = 0, false
	if d := lockedIdle(); d != 0 {
		t.Errorf("a vault without a token drops its key after %s", d)
	}
	tok := useFakeToken(t)
	if err := AddToken(tok.enrol, false, "yubi", func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	idleFor, idleLoaded = 0, false
	if d := lockedIdle(); d != 5*time.Minute {
		t.Errorf("a token vault with 5 minutes set: %s", d)
	}
	st.VaultIdleMinutes = 0
	settings.Save(st)
	idleFor, idleLoaded = 0, false
	if d := lockedIdle(); d != 0 {
		t.Errorf("a token vault without a set time drops its key after %s", d)
	}
}
