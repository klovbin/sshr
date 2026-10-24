package syncclient

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"reflect"

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
// keychain, old is the store the caller read from StoreRef and built ref
// and b from, b is that store opened with the new key, it has to read the
// account before anything changes, a failed save puts the old secret back
func (c *Client) ReplaceStoreKey(old, ref BackendRef, secret string, b Backend) error {
	return c.run(func() error {
		c.Backend = b
		if err := c.load(); err != nil {
			return err
		}
		if c.st.Backend == nil || c.st.Backend.Kind != ref.Kind {
			return fmt.Errorf("this account is not in a sync store of kind %q", ref.Kind)
		}
		// the state may have changed since StoreRef read it, a key for the
		// store the caller saw must not land on another one
		if !sameJSON(c.st.Backend.Config, old.Config) {
			return errors.New("the sync store of this machine changed meanwhile, run sshr sync store-key again")
		}
		if _, _, err := b.Head(); err != nil {
			return fmt.Errorf("the new key does not read this account: %v", err)
		}
		// a key scoped to fewer folders would pass the manifests and fail
		// the next sync, the vault key of this device is read as well
		if c.st.Approver == "" && c.st.Epoch > 0 {
			_, err := b.GetEnvelope(c.st.DeviceID, c.st.Epoch)
			if errors.Is(err, ErrNotFound) {
				return errors.New("the vault key of this device is not delivered yet, run sshr sync once it is, then sshr sync store-key again")
			}
			if err != nil {
				return fmt.Errorf("the new key does not read the vault key of this device: %v", err)
			}
		}
		name := c.storeSecretName()
		oldSecret, hadOld, err := vault.SecretGet(name)
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
			var rerr error
			if hadOld {
				rerr = vault.SecretSet(name, oldSecret)
			} else {
				rerr = vault.SecretDelete(name)
			}
			if rerr != nil {
				return fmt.Errorf("%v, and the keychain kept the new secret while the sync state names the old key (%v), run sshr sync store-key again", err, rerr)
			}
			return err
		}
		return nil
	})
}

// sameJSON compares two JSON values, not their spelling, the state keeps
// its config indented
func sameJSON(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// CheckStoreURL takes the HTTPS address of a store, plain HTTP only to a
// loopback IP, the sync state can be edited and must not send the
// requests in the clear, a user and password in the address would end up
// in the state, what names the address in the errors
func CheckStoreURL(what, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// the address is not repeated, it may hold a password
		return fmt.Errorf("bad %s, it has to look like https://host[:port][/path]", what)
	}
	if u.User != nil {
		return fmt.Errorf("the %s must not carry a user or password, they go apart", what)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		// a loopback address, not the name localhost, a resolver may send
		// that name elsewhere
		if ip := net.ParseIP(u.Hostname()); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("the %s has to be https://, plain http only to this machine: %s", what, u.Redacted())
}
