//go:build !linux

package app

// keychainState sorts a keychain error, the macOS Keychain and the Windows
// Credential Manager are not told apart yet, see #153
func keychainState(err error) error { return nil }
