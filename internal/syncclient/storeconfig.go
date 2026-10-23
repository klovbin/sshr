package syncclient

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"sshr.dev/internal/fileio"
	"sshr.dev/internal/vault"
)

// BackendRef names the store of an account that is not sshr-sync, it is
// kept in the sync state, Config is what OpenBackend needs and never a
// secret, the secret is in the keychain beside the device key
type BackendRef struct {
	Kind   string          `json:"kind"`
	Config json.RawMessage `json:"config"`
}

// storeSecretName is the keychain item of the secret of the store
func (c *Client) storeSecretName() string { return c.prefix() + "store-secret" }

// storeOpenError is a store this machine cannot open from its state, a
// missing secret, a kind it does not know or settings the store refuses,
// unlike a keychain that fails for now
type storeOpenError struct{ error }

func (e storeOpenError) Unwrap() error { return e.error }

// openBackend opens the store a loaded state names, sshr-sync needs none
func (c *Client) openBackend() error {
	if c.Backend != nil || c.st.Backend == nil {
		return nil
	}
	if c.OpenBackend == nil {
		return storeOpenError{fmt.Errorf("this sshr cannot open a sync store of kind %q", c.st.Backend.Kind)}
	}
	secret, ok, err := vault.SecretGet(c.storeSecretName())
	if err != nil {
		return err
	}
	if !ok {
		return storeOpenError{errors.New("the secret of the sync store is gone from the keychain, run sshr sync leave and join again")}
	}
	b, err := c.OpenBackend(*c.st.Backend, string(secret))
	if err != nil {
		return storeOpenError{err}
	}
	c.Backend = b
	return nil
}

// keepBackend writes the store a new account or join uses into the state,
// the secret waits for saveNew
func (c *Client) keepBackend() {
	if c.BackendRef == nil {
		return
	}
	ref := *c.BackendRef
	c.st.Backend = &ref
}

// saveNew writes the state of an account the store has just taken, the
// secret of the store goes into the keychain only now, a failed init or
// join leaves no secret that no state names
func (c *Client) saveNew() error {
	if c.BackendRef == nil || c.StoreSecret == "" {
		return c.save()
	}
	if err := vault.SecretSet(c.storeSecretName(), []byte(c.StoreSecret)); err != nil {
		return err
	}
	if err := c.save(); err != nil {
		vault.SecretDelete(c.storeSecretName())
		return err
	}
	return nil
}

// ProbeCreate checks that store refuses a second create of one name, a
// store without that write would let two devices fork the history, the
// probe object is deleted again, a key that cannot delete is an error
// too, removing a device deletes its record
func ProbeCreate(store ObjectStore) (err error) {
	var b [8]byte
	rand.Read(b[:])
	name := "probe/" + hex.EncodeToString(b[:])
	if err := store.Create(name, []byte("first")); err != nil {
		return fmt.Errorf("the store did not take a create: %v", err)
	}
	defer func() {
		if derr := store.Delete(name); derr != nil && err == nil {
			err = fmt.Errorf("the store did not delete the probe object %s, delete it by hand, sync needs to delete objects: %v", name, derr)
		}
	}()
	err = store.Create(name, []byte("second"))
	if err == nil {
		return errors.New("the store wrote over an object it should have refused, it cannot keep two devices from forking the history, use another store or sshr-sync")
	}
	if !errors.Is(err, ErrExists) {
		return fmt.Errorf("the store answered a second create with: %v", err)
	}
	return nil
}

// StoreRef is the store the sync state of this machine names, nil for an
// account on sshr-sync, it reads the state without opening the store, so
// it works while the secret of the store is gone
func (c *Client) StoreRef() (*BackendRef, error) {
	b, err := fileio.ReadFileShared(c.statePath())
	if os.IsNotExist(err) {
		return nil, ErrNotSetUp
	}
	if err != nil {
		return nil, err
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return st.Backend, nil
}

// ReplaceStoreKey puts a new key of the same store into the state and the
// keychain, b is that store opened with the new key, it has to read the
// account before anything changes, a failed save puts the old secret back
func (c *Client) ReplaceStoreKey(ref BackendRef, secret string, b Backend) error {
	return c.run(func() error {
		c.Backend = b
		if err := c.load(); err != nil {
			return err
		}
		if c.st.Backend == nil || c.st.Backend.Kind != ref.Kind {
			return fmt.Errorf("this account is not in a sync store of kind %q", ref.Kind)
		}
		if _, _, err := b.Head(); err != nil {
			return fmt.Errorf("the new key does not read this account: %v", err)
		}
		name := c.storeSecretName()
		old, hadOld, err := vault.SecretGet(name)
		if err != nil {
			return err
		}
		if err := vault.SecretSet(name, []byte(secret)); err != nil {
			return err
		}
		prev := c.st.Backend
		c.st.Backend = &ref
		if err := c.save(); err != nil {
			c.st.Backend = prev
			if hadOld {
				vault.SecretSet(name, old)
			} else {
				vault.SecretDelete(name)
			}
			return err
		}
		return nil
	})
}
