package vault

import (
	"sync"
	"time"

	"sshr.dev/internal/settings"
)

// A running sshr forgets the vault key some time after its last use, the
// window, sshr serve and sshr mcp run for hours, a key kept all that time
// is there for anything that reads the memory, the next use reads it from
// the keychain again without a word, under a passphrase the key is kept
// for the whole run, asking again would stop sshr serve and sshr mcp at
// the next use with no one to answer, inside the lock of the key

var (
	// keyUsedAt and idleTimer are under vaultMu
	keyUsedAt time.Time
	idleTimer *time.Timer

	idleOnce sync.Once
	idleFor  time.Duration
	// idleOverride replaces the setting in tests, 0 leaves the setting
	idleOverride time.Duration
)

// keyIdle is how long the key is kept after its last use, 0 for the whole
// run, always 0 under a passphrase, read once per process
func keyIdle() time.Duration {
	if idleOverride != 0 {
		return idleOverride
	}
	idleOnce.Do(func() {
		if Mode() == ModePassphrase {
			idleFor = 0
			return
		}
		st, err := settings.Load()
		if err != nil {
			idleFor = settings.DefaultVaultIdle
			return
		}
		idleFor = st.VaultIdle()
	})
	return idleFor
}

// touchKey marks the key as used now and arms the timer that forgets it,
// vaultMu is held
func touchKey() {
	keyUsedAt = time.Now()
	if idleTimer != nil {
		return
	}
	if d := keyIdle(); d > 0 {
		idleTimer = time.AfterFunc(d, dropIdleKey)
	}
}

// dropIdleKey forgets the key when it was not used for the idle time, the
// bytes are zeroed, a cipher made from the key holds a copy of its own, so
// a seal or an open in progress is not affected
func dropIdleKey() {
	vaultMu.Lock()
	defer vaultMu.Unlock()
	idleTimer = nil
	if vaultKey == nil {
		return
	}
	if left := keyIdle() - time.Since(keyUsedAt); left > 0 {
		idleTimer = time.AfterFunc(left, dropIdleKey)
		return
	}
	clear(vaultKey)
	vaultKey = nil
}

// stopIdle stops the timer, vaultMu is held
func stopIdle() {
	if idleTimer != nil {
		idleTimer.Stop()
		idleTimer = nil
	}
}
