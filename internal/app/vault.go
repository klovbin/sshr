package app

import (
	"fmt"

	"sshr.dev/internal/vault"
)

// The vault lives in package vault, it runs no program, the system
// keychain and the passphrase prompt that run programs are set here
func init() {
	vault.SetKeychain(systemKeychain{})
	vault.SetPrompt(promptPassphrase)
	vault.SetToken(askFIDO2)
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

// NewVaultRecoveryCode replaces the recovery code of the vault kept in
// vault-key.json, confirm shows the code and gets a part of it back before
// anything is written
func NewVaultRecoveryCode(confirm func(code string) error) error {
	return vault.NewRecoveryCode(confirm)
}

// VaultSlot describes a slot of vault-key.json
type VaultSlot = vault.SlotInfo

// VaultSlots lists the slots of the vault kept in vault-key.json
func VaultSlots() ([]VaultSlot, error) { return vault.Slots() }

// vaultLabelMax is the longest label a token slot gets
const vaultLabelMax = 64

// AddVaultToken adds the one plugged FIDO2 token to the vault kept in
// vault-key.json, confirm shows the recovery code the first token brings
func AddVaultToken(label string, confirm func(code string) error) error {
	label = cleanText(label)
	if len(label) > vaultLabelMax {
		return fmt.Errorf("the label is longer than %d bytes", vaultLabelMax)
	}
	return vault.AddToken(enrolFIDO2, false, label, confirm)
}

// RemoveVaultSlot removes a slot of vault-key.json, never the last way in
// that is not a token unless two tokens stay
func RemoveVaultSlot(id string) error { return vault.RemoveSlot(id) }

// VaultRecoveryUsed tells whether a recovery code opened the vault in
// this run
func VaultRecoveryUsed() bool { return vault.RecoveryUsed() }

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
