package vault

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

// the vault key is zeroed and forgotten after the idle time, a use within
// it keeps the key, the next use reads the same key from the keychain
func TestVaultKeyIdleDrop(t *testing.T) {
	useMockKeychain(t)
	idleOverride = 80 * time.Millisecond
	t.Cleanup(func() {
		vaultMu.Lock()
		stopIdle()
		vaultMu.Unlock()
		idleOverride = 0
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
	time.Sleep(50 * time.Millisecond)
	if _, err := Key(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
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
	idleOnce, idleFor = sync.Once{}, 0
	t.Cleanup(func() { idleOnce, idleFor = sync.Once{}, 0 })
	if d := keyIdle(); d != 0 {
		t.Fatalf("a passphrase vault drops its key after %s", d)
	}
}
