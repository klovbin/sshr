//go:build linux

package app

import (
	"errors"
	"fmt"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/zalando/go-keyring"
)

// the errors go-keyring gives for a missing Secret Service and a locked
// keyring are told apart, and stay ErrNoKeychain for the app (#169)
func TestKeychainStatesOnLinux(t *testing.T) {
	for _, c := range []struct {
		err  error
		want error
	}{
		{dbus.Error{Name: "org.freedesktop.DBus.Error.ServiceUnknown"}, ErrKeychainMissing},
		{dbus.Error{Name: "org.freedesktop.Secret.Error.NoSuchObject", Body: []any{"no default collection"}}, ErrKeychainMissing},
		{errors.New("dial unix /run/user/1000/bus: connect: no such file or directory"), ErrKeychainMissing},
		{fmt.Errorf("failed to unlock correct collection '%v'", "/org/freedesktop/secrets/aliases/default"), ErrKeychainLocked},
	} {
		keyring.MockInitWithError(c.err)
		resetVault(t)
		_, err := VaultKey()
		if !errors.Is(err, c.want) || !errors.Is(err, ErrNoKeychain) {
			t.Errorf("%v: got %v, want %v", c.err, err, c.want)
		}
	}
	keyring.MockInit()
}
