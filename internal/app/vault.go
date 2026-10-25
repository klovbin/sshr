package app

import "sshr.dev/internal/vault"

// The vault lives in package vault, it runs no program, the system
// keychain and the passphrase prompt that run programs are set here
func init() {
	vault.SetKeychain(systemKeychain{})
	vault.SetPrompt(promptPassphrase)
}

// keyringService is the service name of every item sshr keeps in the
// system keychain
const keyringService = "sshr"

// Seals of passwords and keys, see package vault
const (
	sealPrefix  = vault.SealPrefix
	sealPrefix2 = vault.SealPrefix2
)

// The modes of the vault key, see vault.Mode
const (
	VaultKeychain   = vault.ModeKeychain
	VaultPassphrase = vault.ModePassphrase
)

// Keychain is where sshr keeps its own secrets, see vault.Keychain
type Keychain = vault.Keychain

// KeychainError carries why the keychain could not be used
type KeychainError = vault.KeychainError

// The errors of the vault, the same values as in package vault
var (
	ErrNoKeychain      = vault.ErrNoKeychain
	ErrKeychainMissing = vault.ErrKeychainMissing
	ErrKeychainLocked  = vault.ErrKeychainLocked
	ErrKeychainTimeout = vault.ErrKeychainTimeout
	ErrSealBroken      = vault.ErrSealBroken
	ErrVaultKeyLost    = vault.ErrVaultKeyLost
	ErrBadPassphrase   = vault.ErrBadPassphrase
	ErrNoPassphrase    = vault.ErrNoPassphrase
	errSecretNotFound  = vault.ErrSecretNotFound
)

// VaultKey returns the vault key, see vault.Key
func VaultKey() ([]byte, error) { return vault.Key() }

// VaultMode is where the vault key lives, see vault.Mode
func VaultMode() string { return vault.Mode() }

// CheckKeychain tells whether saved secrets can be used here
func CheckKeychain() error { return vault.CheckKeychain() }

// SecretGet reads a named secret of sshr
func SecretGet(name string) ([]byte, bool, error) { return vault.SecretGet(name) }

// SecretSet stores a named secret of sshr
func SecretSet(name string, value []byte) error { return vault.SecretSet(name, value) }

// SecretDelete removes a named secret of sshr
func SecretDelete(name string) error { return vault.SecretDelete(name) }

// MoveSecrets moves named secrets between the keychain and the vault file
func MoveSecrets(names []string, toFile bool) error { return vault.MoveSecrets(names, toFile) }

// ErrKeychainCopyLeft means the vault is under the passphrase and the
// system keychain still holds the vault key
var ErrKeychainCopyLeft = vault.ErrKeychainCopyLeft

// SetVaultPassphrase moves the vault key under a passphrase
func SetVaultPassphrase(pass string, secretNames []string) error {
	return vault.SetPassphrase(pass, secretNames)
}

// UseKeychainVault moves the vault key back into the system keychain
func UseKeychainVault(secretNames []string) error { return vault.UseKeychain(secretNames) }

func sealFor(plain []byte, hostID, field, dest string) (string, error) {
	return vault.SealFor(plain, hostID, field, dest)
}

func unsealFor(blob, hostID, field, dest string) ([]byte, error) {
	return vault.UnsealFor(blob, hostID, field, dest)
}

func unseal(blob, hostID, field string) ([]byte, error) { return vault.Unseal(blob, hostID, field) }
