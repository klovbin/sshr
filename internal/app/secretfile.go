package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/zalando/go-keyring"
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
		return "", keyring.ErrNotFound
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
			return keyring.ErrNotFound
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
// passphrase vault file, or back when toFile is false, a name that is in
// neither is skipped, used when the vault mode changes
func MoveSecrets(names []string, toFile bool) error {
	var from, to Keychain = keychain, fileKeychain{}
	if !toFile {
		from, to = fileKeychain{}, keychain
	}
	for _, name := range names {
		v, err := callStore(from, func(k Keychain) (string, error) { return k.Get(name) })
		if errors.Is(err, keyring.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if _, err := callStore(to, func(k Keychain) (string, error) { return "", k.Set(name, v) }); err != nil {
			return err
		}
	}
	return nil
}
