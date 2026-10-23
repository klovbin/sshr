//go:build linux

package app

import (
	"errors"
	"strings"

	"github.com/godbus/dbus/v5"
)

// keychainState sorts an error of the Secret Service into missing (no
// session bus, the service is not running, no default collection) and
// locked (the unlock prompt was dismissed), what go-keyring returns
func keychainState(err error) error {
	var de dbus.Error
	if errors.As(err, &de) {
		switch de.Name {
		case "org.freedesktop.DBus.Error.ServiceUnknown", "org.freedesktop.DBus.Error.NameHasNoOwner",
			"org.freedesktop.Secret.Error.NoSuchObject", "org.freedesktop.DBus.Error.UnknownObject":
			return ErrKeychainMissing
		}
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "failed to unlock correct collection"):
		return ErrKeychainLocked
	case strings.Contains(msg, "DBUS_SESSION_BUS_ADDRESS"), strings.Contains(msg, "dbus-launch"),
		strings.Contains(msg, "dbus: authentication failed"),
		strings.Contains(msg, "/bus:") && (strings.Contains(msg, "no such file") || strings.Contains(msg, "connection refused")):
		return ErrKeychainMissing
	}
	return nil
}
