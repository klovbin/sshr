package vault

import (
	"bytes"
	"os"
	"testing"
	"time"

	"sshr.dev/internal/settings"
)

// the vault key is zeroed and forgotten after the idle time, a use within
// it keeps the key, the next use reads the same key from the keychain
func TestVaultKeyIdleDrop(t *testing.T) {
	useMockKeychain(t)
	// written under the lock the timer reads it with, a margin of 150 ms
	// on each side keeps the test steady on a loaded runner (#347)
	const idle = 300 * time.Millisecond
	vaultMu.Lock()
	idleOverride = idle
	vaultMu.Unlock()
	t.Cleanup(func() {
		vaultMu.Lock()
		stopIdle()
		idleOverride = 0
		vaultMu.Unlock()
	})
	k1, err := Key()
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(k1)
	vaultMu.Lock()
	cached := vaultKey
	vaultMu.Unlock()
	held := func() bool {
		vaultMu.Lock()
		defer vaultMu.Unlock()
		return vaultKey != nil
	}
	// a use halfway keeps the key past the first deadline
	time.Sleep(idle / 2)
	if _, err := Key(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(idle / 2)
	if !held() {
		t.Fatal("the key was dropped although it was used within the idle time")
	}
	deadline := time.Now().Add(2 * time.Second)
	for held() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if held() {
		t.Fatal("the key was kept past the idle time")
	}
	if !bytes.Equal(cached, make([]byte, len(cached))) {
		t.Error("the dropped key was not zeroed")
	}
	// the caller's copy is its own, the drop does not change it (#345)
	if !bytes.Equal(k1, want) {
		t.Error("the copy a caller got was changed by the drop")
	}
	k2, err := Key()
	if err != nil || !bytes.Equal(k2, want) {
		t.Fatalf("the key read again differs: %v", err)
	}
}

// under a passphrase the key is kept for the whole run, asking again
// would block sshr serve and sshr mcp (#344)
func TestPassphraseVaultKeepsTheKey(t *testing.T) {
	t.Setenv("SSHR_VAULT", ModePassphrase)
	idleFor, idleLoaded = 0, false
	t.Cleanup(func() { idleFor, idleLoaded = 0, false })
	if d := lockedIdle(); d != 0 {
		t.Fatalf("a passphrase vault drops its key after %s", d)
	}
}

// a settings file that does not read gives the default once and is read
// again on the next use, a fixed file then counts (#346)
func TestIdleTimeReadAgainAfterAFailedLoad(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SSHR_VAULT", ModeKeychain)
	idleFor, idleLoaded = 0, false
	t.Cleanup(func() { idleFor, idleLoaded = 0, false })
	path, err := settings.Path()
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte("{half"), 0o600)
	if d := lockedIdle(); d != settings.DefaultVaultIdle {
		t.Fatalf("a broken file gave %s", d)
	}
	os.WriteFile(path, []byte(`{"vault_idle_minutes": -1}`), 0o600)
	if d := lockedIdle(); d != 0 {
		t.Fatalf("the fixed file was not read again, got %s", d)
	}
}

// lockedIdle is keyIdle with the lock it expects
func lockedIdle() time.Duration {
	vaultMu.Lock()
	defer vaultMu.Unlock()
	return keyIdle()
}
