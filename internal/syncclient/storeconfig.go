package syncclient

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

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

// openBackend opens the store a loaded state names, sshr-sync needs none
func (c *Client) openBackend() error {
	if c.Backend != nil || c.st.Backend == nil {
		return nil
	}
	if c.OpenBackend == nil {
		return fmt.Errorf("this sshr cannot open a sync store of kind %q", c.st.Backend.Kind)
	}
	secret, ok, err := vault.SecretGet(c.storeSecretName())
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("the secret of the sync store is gone from the keychain, run sshr sync leave and join again")
	}
	b, err := c.OpenBackend(*c.st.Backend, string(secret))
	if err != nil {
		return err
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
