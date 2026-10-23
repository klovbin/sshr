package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// fileKeychain keeps the named secrets of sshr (the keys of the sync
// device) in ~/.sshr/vault/secrets.json when the vault is under a
// passphrase, each value sealed with the vault key and its name, a machine
// without a system keychain can sync then
type fileKeychain struct{}

type secretsFile struct {
	Version int               `json:"version"`
	Secrets map[string]string `json:"secrets"`
}

const secretsWait = 10 * time.Second

func secretsPath() (string, error) {
	lock, err := vaultLockPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(lock), "secrets.json"), nil
}

func secretAAD(name string) []byte { return []byte("sshr\x00secret\x00" + name) }

func readSecrets(path string) (*secretsFile, error) {
	f := &secretsFile{Version: 1, Secrets: map[string]string{}}
	b, err := ReadFileShared(path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, f); err != nil {
		return nil, errors.New(path + " is damaged: " + err.Error())
	}
	if f.Secrets == nil {
		f.Secrets = map[string]string{}
	}
	return f, nil
}

func (fileKeychain) Get(name string) (string, error) {
	path, err := secretsPath()
	if err != nil {
		return "", err
	}
	f, err := readSecrets(path)
	if err != nil {
		return "", err
	}
	sealed, ok := f.Secrets[name]
	if !ok {
		return "", errSecretNotFound
	}
	plain, err := unsealRaw(sealed, secretAAD(name))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// change edits secrets.json under a lock of its own, two sshr processes do
// not lose each other's secrets
func (fileKeychain) change(edit func(map[string]string) error) error {
	path, err := secretsPath()
	if err != nil {
		return err
	}
	unlock, err := waitLock(path+".lock", "saving a secret", secretsWait)
	if err != nil {
		return err
	}
	defer unlock()
	f, err := readSecrets(path)
	if err != nil {
		return err
	}
	if err := edit(f.Secrets); err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, append(b, '\n'), 0o600)
}

func (k fileKeychain) Set(name, value string) error {
	sealed, err := sealRaw([]byte(value), secretAAD(name))
	if err != nil {
		return err
	}
	return k.change(func(m map[string]string) error {
		m[name] = sealed
		return nil
	})
}

func (k fileKeychain) Delete(name string) error {
	return k.change(func(m map[string]string) error {
		if _, ok := m[name]; !ok {
			return errSecretNotFound
		}
		delete(m, name)
		return nil
	})
}

// secretStore is where the named secret goes: the vault key itself always
// in the system keychain (the passphrase vault has its own file), the
// others in the file when the vault is under a passphrase
func secretStore(name string) Keychain {
	if name != keyringUser && VaultMode() == VaultPassphrase {
		return fileKeychain{}
	}
	return keychain
}

// MoveSecrets moves the named secrets from the system keychain to the
// passphrase vault file, or back when toFile is false: each value is read
// back from the target and only then removed from the source, a name in
// neither place is skipped, a keychain that is not there holds nothing to
// move, a move that fails halfway takes back what it moved, the mode
// reads one place and a key left in the other looks lost
func MoveSecrets(names []string, toFile bool) error {
	_, err := moveSecretsBack(names, toFile)
	return err
}

// moveSecretsBack is MoveSecrets that also says which names it moved, a
// caller that fails later takes back only those
func moveSecretsBack(names []string, toFile bool) ([]string, error) {
	moved, err := moveSecrets(names, toFile)
	if err == nil {
		return moved, nil
	}
	if _, berr := moveSecrets(moved, !toFile); berr != nil {
		return nil, fmt.Errorf("%v, %d of the keys stayed in the new place, run the same command again: %v", err, len(moved), berr)
	}
	return nil, err
}

func moveSecrets(names []string, toFile bool) ([]string, error) {
	var from, to Keychain = keychain, fileKeychain{}
	if !toFile {
		from, to = fileKeychain{}, keychain
	}
	var moved []string
	for _, name := range names {
		v, err := callStore(from, func(k Keychain) (string, error) { return k.Get(name) })
		if errors.Is(err, errSecretNotFound) || (toFile && errors.Is(err, ErrKeychainMissing)) {
			continue
		}
		if err != nil {
			return moved, fmt.Errorf("the secret %s does not read where it is now, it may be damaged or sealed with another key, remove it there if it is not needed: %w", name, err)
		}
		if _, err := callStore(to, func(k Keychain) (string, error) { return "", k.Set(name, v) }); err != nil {
			return moved, err
		}
		back, err := callStore(to, func(k Keychain) (string, error) { return k.Get(name) })
		if err != nil || back != v {
			return moved, fmt.Errorf("the secret %s did not read back from its new place, it stays where it was", name)
		}
		if _, err := callStore(from, func(k Keychain) (string, error) { return "", k.Delete(name) }); err != nil && !errors.Is(err, errSecretNotFound) {
			return moved, err
		}
		moved = append(moved, name)
	}
	return moved, nil
}
