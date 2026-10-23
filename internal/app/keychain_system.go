package app

import (
	"errors"

	"github.com/zalando/go-keyring"
)

// systemKeychain is the keychain of the system through go-keyring: Secret
// Service on Linux, Keychain on macOS, Credential Manager on Windows
type systemKeychain struct{}

func (systemKeychain) Get(name string) (string, error) {
	v, err := keyring.Get(keyringService, name)
	return v, notFound(err)
}
func (systemKeychain) Set(name, value string) error { return keyring.Set(keyringService, name, value) }
func (systemKeychain) Delete(name string) error {
	return notFound(keyring.Delete(keyringService, name))
}

// State sorts an error of the system keychain into missing or locked
func (systemKeychain) State(err error) error { return keychainState(err) }

// notFound turns the not-found error of go-keyring into errSecretNotFound
func notFound(err error) error {
	if errors.Is(err, keyring.ErrNotFound) {
		return errSecretNotFound
	}
	return err
}
