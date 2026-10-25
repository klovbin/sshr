package vault

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

// passphraseVault turns the passphrase vault on and returns its key, the
// prompt answers with *answer
func passphraseVault(t *testing.T, answer *string) []byte {
	t.Helper()
	useMockKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	cheapPassphrase(t, answer)
	key, err := Key()
	if err != nil {
		t.Fatal(err)
	}
	if err := SetPassphrase(*answer, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { recoveryUsed.Store(false) })
	return key
}

// a recovery code opens the vault in place of the passphrase, the
// passphrase still does, a new code replaces the old one
func TestRecoveryCodeOpensTheVault(t *testing.T) {
	answer := "correct horse battery"
	key := passphraseVault(t, &answer)
	var code string
	if err := NewRecoveryCode(func(c string) error { code = c; return nil }); err != nil {
		t.Fatal(err)
	}
	_, kf, err := readKeyFile()
	if err != nil || kf == nil || !hasSlot(kf, slotRecovery) || !hasSlot(kf, slotPassphrase) {
		t.Fatalf("the file after the code: %v", err)
	}

	forgetVaultKey()
	if got, err := Key(); err != nil || !bytes.Equal(got, key) || RecoveryUsed() {
		t.Fatalf("the passphrase after a code was added: %v used=%v", err, RecoveryUsed())
	}

	forgetVaultKey()
	answer = strings.ToLower(strings.ReplaceAll(code, " ", "-"))
	if got, err := Key(); err != nil || !bytes.Equal(got, key) || !RecoveryUsed() {
		t.Fatalf("the recovery code: %v used=%v", err, RecoveryUsed())
	}

	old := code
	if err := NewRecoveryCode(func(c string) error { code = c; return nil }); err != nil {
		t.Fatal(err)
	}
	if RecoveryUsed() {
		t.Error("a new code left the used mark")
	}
	forgetVaultKey()
	answer = old
	if _, err := Key(); !errors.Is(err, ErrBadRecoveryCode) {
		t.Errorf("the replaced code: %v", err)
	}
	forgetVaultKey()
	answer = code
	if got, err := Key(); err != nil || !bytes.Equal(got, key) {
		t.Errorf("the new code: %v", err)
	}
}

// a code that was not confirmed changes nothing, a code with a typo names
// its group, the keychain vault has no recovery code
func TestRecoveryCodeRefusals(t *testing.T) {
	answer := "correct horse battery"
	passphraseVault(t, &answer)
	path, _ := passphraseFilePath()
	before, _ := os.ReadFile(path)
	var code string
	if err := NewRecoveryCode(func(c string) error { code = c; return errors.New("not written down") }); err == nil {
		t.Fatal("a refused confirm saved the code")
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Error("the file changed without a confirm")
	}

	NewRecoveryCode(func(c string) error { code = c; return nil })
	groups := strings.Fields(code)
	g := []byte(groups[1])
	if g[0] == 'A' {
		g[0] = 'B'
	} else {
		g[0] = 'A'
	}
	groups[1] = string(g)
	_, kf, _ := readKeyFile()
	if _, err := openRecoverySlots(kf, strings.Join(groups, " ")); err == nil || !strings.Contains(err.Error(), "group 2") {
		t.Errorf("a typo: %v", err)
	}

	t.Setenv("SSHR_VAULT", ModeKeychain)
	if err := NewRecoveryCode(func(string) error { return nil }); err == nil {
		t.Error("a recovery code for the keychain vault")
	}
}

// a code typed with a typo at the prompt is named by its group and not
// taken for a wrong passphrase, a file another process changed while the
// code was shown is not overwritten
func TestRecoveryCodeTypoAndChangedFile(t *testing.T) {
	answer := "correct horse battery"
	passphraseVault(t, &answer)
	var code string
	if err := NewRecoveryCode(func(c string) error { code = c; return nil }); err != nil {
		t.Fatal(err)
	}
	groups := strings.Fields(code)
	g := []byte(groups[0])
	if g[0] == 'A' {
		g[0] = 'B'
	} else {
		g[0] = 'A'
	}
	groups[0] = string(g)
	forgetVaultKey()
	answer = strings.Join(groups, " ")
	if _, err := Key(); err == nil || errors.Is(err, ErrBadPassphrase) || !strings.Contains(err.Error(), "group 1") {
		t.Errorf("a typo in the code at the prompt: %v", err)
	}

	answer = "correct horse battery"
	path, _ := passphraseFilePath()
	err := NewRecoveryCode(func(string) error {
		// another sshr changes the passphrase meanwhile
		b, _ := os.ReadFile(path)
		return os.WriteFile(path, append(b, ' '), 0o600)
	})
	if err == nil || !strings.Contains(err.Error(), "changed") {
		t.Errorf("a file changed while the code was shown: %v", err)
	}
}
