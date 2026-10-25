package vault

import (
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

	// idleFor is the idle time read from the settings, idleLoaded tells
	// that it was read, both under vaultMu
	idleFor    time.Duration
	idleLoaded bool
	// idleOverride replaces the setting in tests, 0 leaves the setting,
	// under vaultMu
	idleOverride time.Duration
)

// keyIdle is how long the key is kept after its last use, 0 for the whole
// run, read once per process, a settings file that does not read gives the
// default this time and is read again next time, vaultMu is held, a vault
// in vault-key.json keeps the key for the whole run, sshr serve and sshr
// mcp have no one to ask the passphrase, a vault with a token slot drops
// it when vault_idle_minutes is set, the key can be touched again
func keyIdle() time.Duration {
	if idleOverride != 0 {
		return idleOverride
	}
	if idleLoaded {
		return idleFor
	}
	if Mode() == ModePassphrase {
		st, err := settings.Load()
		if err != nil || st.VaultIdleMinutes <= 0 {
			// the key is kept, a broken settings file is read again next time
			idleFor, idleLoaded = 0, err == nil
			return 0
		}
		token, err := tokenVault()
		if err != nil {
			return 0
		}
		idleFor, idleLoaded = 0, true
		if token {
			idleFor = st.VaultIdle()
		}
		return idleFor
	}
	st, err := settings.Load()
	if err != nil {
		return settings.DefaultVaultIdle
	}
	idleFor, idleLoaded = st.VaultIdle(), true
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

// tokenVault tells whether vault-key.json has a token slot
func tokenVault() (bool, error) {
	_, kf, err := readKeyFile()
	return err == nil && hasSlot(kf, slotFIDO2), err
}

// slotsChanged makes the idle time read again, a token slot added or
// removed in this run changes it
func slotsChanged() {
	vaultMu.Lock()
	idleLoaded = false
	vaultMu.Unlock()
}
