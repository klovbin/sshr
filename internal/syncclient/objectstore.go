package syncclient

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"sshr.dev/internal/syncproto"
)

// ObjectStore is a plain store of named objects, an S3 bucket or a WebDAV
// folder, it keeps one sync account, the one write a sync relies on is
// Create, which fails with ErrExists when the name is taken
type ObjectStore interface {
	// Get reads an object, ErrNotFound when there is none
	Get(name string) ([]byte, error)
	// Put writes an object over any that is there
	Put(name string, data []byte) error
	// Create writes an object only when the name is free, ErrExists
	// otherwise, two devices creating the same name at once see one win
	Create(name string, data []byte) error
	// Delete removes an object, a missing one is no error
	Delete(name string) error
	// List names the objects that start with prefix
	List(prefix string) ([]string, error)
}

// ErrExists means Create found the name taken
var ErrExists = errors.New("the object exists already")

// ObjectBackend runs a sync account in an ObjectStore: manifests are
// created as manifests/<counter> and a device that loses the race to
// create the next one pulls and tries again, as with sshr-sync, there is
// no server, so no token keeps a removed or waiting device out, the store
// credential does, see SECURITY.md
type ObjectBackend struct {
	Store ObjectStore
}

const (
	objAccount   = "account"
	objDevices   = "devices/"
	objEnvelopes = "envelopes/"
	objBlobs     = "blobs/"
	objManifests = "manifests/"
)

func manifestName(counter uint64) string { return fmt.Sprintf("%s%020d", objManifests, counter) }

func envelopeName(id string, epoch int) string {
	return fmt.Sprintf("%s%s/%010d", objEnvelopes, id, epoch)
}

// CreateAccount claims the store for a new account, a store that holds
// one already is refused
func (o ObjectBackend) CreateAccount(dev []byte) ([]byte, error) {
	var req syncproto.NewAccountRequest
	if err := json.Unmarshal(dev, &req); err != nil {
		return nil, err
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	account := hex.EncodeToString(b[:])
	if err := o.Store.Create(objAccount, []byte(account)); err != nil {
		if errors.Is(err, ErrExists) {
			return nil, errors.New("the store holds a sync account already, join it with an invite or empty the store")
		}
		return nil, err
	}
	rec, _ := json.Marshal(syncproto.DeviceRecord{Device: req.Device, Active: true})
	if err := o.Store.Put(objDevices+req.Device.ID, rec); err != nil {
		return nil, err
	}
	return json.Marshal(syncproto.TokenResponse{Account: account})
}

// Join adds a device that waits for approval
func (o ObjectBackend) Join(dev []byte) ([]byte, error) {
	var req syncproto.NewAccountRequest
	if err := json.Unmarshal(dev, &req); err != nil {
		return nil, err
	}
	account, err := o.Store.Get(objAccount)
	if errors.Is(err, ErrNotFound) {
		return nil, errors.New("the store holds no sync account")
	}
	if err != nil {
		return nil, err
	}
	rec, _ := json.Marshal(syncproto.DeviceRecord{Device: req.Device})
	if err := o.Store.Create(objDevices+req.Device.ID, rec); err != nil {
		if errors.Is(err, ErrExists) {
			return nil, errors.New("device already joined")
		}
		return nil, err
	}
	return json.Marshal(syncproto.TokenResponse{Account: string(account)})
}

func (o ObjectBackend) Devices() ([]byte, error) {
	names, err := o.Store.List(objDevices)
	if err != nil {
		return nil, err
	}
	out := []syncproto.DeviceRecord{}
	for _, n := range names {
		b, err := o.Store.Get(n)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var rec syncproto.DeviceRecord
		if err := json.Unmarshal(b, &rec); err != nil {
			return nil, fmt.Errorf("%s: %v", n, err)
		}
		out = append(out, rec)
	}
	return json.Marshal(out)
}

func (o ObjectBackend) Activate(id string) error {
	b, err := o.Store.Get(objDevices + id)
	if err != nil {
		return err
	}
	var rec syncproto.DeviceRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return err
	}
	rec.Active = true
	b, _ = json.Marshal(rec)
	return o.Store.Put(objDevices+id, b)
}

// RemoveDevice takes the device and its envelopes out, the device keeps
// whatever access the store credential gives it
func (o ObjectBackend) RemoveDevice(id string) error {
	if _, err := o.Store.Get(objDevices + id); err != nil {
		return err
	}
	envs, err := o.Store.List(objEnvelopes + id + "/")
	if err != nil {
		return err
	}
	for _, n := range envs {
		if err := o.Store.Delete(n); err != nil {
			return err
		}
	}
	return o.Store.Delete(objDevices + id)
}

// newestEnvelope is the name and epoch of the newest envelope of id
func (o ObjectBackend) newestEnvelope(id string) (string, int, error) {
	names, err := o.Store.List(objEnvelopes + id + "/")
	if err != nil {
		return "", 0, err
	}
	best, epoch := "", 0
	for _, n := range names {
		e, err := strconv.Atoi(strings.TrimPrefix(n, objEnvelopes+id+"/"))
		if err == nil && e > epoch {
			best, epoch = n, e
		}
	}
	return best, epoch, nil
}

// PutEnvelope keeps one envelope per epoch, an older one never covers a
// newer one
func (o ObjectBackend) PutEnvelope(id string, env []byte) error {
	var e syncproto.Envelope
	if err := json.Unmarshal(env, &e); err != nil {
		return err
	}
	if _, newest, err := o.newestEnvelope(id); err != nil {
		return err
	} else if newest > e.Epoch {
		return ErrStaleEpoch
	}
	return o.Store.Put(envelopeName(id, e.Epoch), env)
}

func (o ObjectBackend) GetEnvelope(id string) ([]byte, error) {
	name, _, err := o.newestEnvelope(id)
	if err != nil {
		return nil, err
	}
	if name == "" {
		return nil, ErrNotFound
	}
	return o.Store.Get(name)
}

func (o ObjectBackend) PutBlob(hash string, blob []byte) error {
	return o.Store.Put(objBlobs+hash, blob)
}

func (o ObjectBackend) GetBlob(hash string) ([]byte, error) {
	return o.Store.Get(objBlobs + hash)
}

// manifests are the counters of the stored manifests, in order
func (o ObjectBackend) manifests() ([]uint64, error) {
	names, err := o.Store.List(objManifests)
	if err != nil {
		return nil, err
	}
	var out []uint64
	for _, n := range names {
		if c, err := strconv.ParseUint(strings.TrimPrefix(n, objManifests), 10, 64); err == nil {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func (o ObjectBackend) Head() (uint64, []byte, error) {
	all, err := o.manifests()
	if err != nil {
		return 0, nil, err
	}
	if len(all) == 0 {
		return 0, nil, ErrNotFound
	}
	last := all[len(all)-1]
	b, err := o.Store.Get(manifestName(last))
	return last, b, err
}

func (o ObjectBackend) ManifestsAfter(n uint64) ([]byte, error) {
	all, err := o.manifests()
	if err != nil {
		return nil, err
	}
	out := []json.RawMessage{}
	for _, c := range all {
		if c <= n {
			continue
		}
		b, err := o.Store.Get(manifestName(c))
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return json.Marshal(out)
}

// PutManifest creates manifests/<expect+1>, a device that created it first
// wins, every blob the manifest names has to be there, no server checks
// that here
func (o ObjectBackend) PutManifest(expect uint64, signed []byte) error {
	var sm syncproto.Signed
	if err := json.Unmarshal(signed, &sm); err != nil {
		return err
	}
	var m syncproto.Manifest
	if err := json.Unmarshal(sm.Body, &m); err != nil {
		return err
	}
	if m.Counter != expect+1 {
		return fmt.Errorf("manifest counter %d does not follow %d", m.Counter, expect)
	}
	for id, e := range m.Entries {
		if e.Hash == "" {
			continue
		}
		if _, err := o.Store.Get(objBlobs + e.Hash); err != nil {
			return fmt.Errorf("the blob of %s is not in the store: %v", short(id, 8), err)
		}
	}
	err := o.Store.Create(manifestName(m.Counter), signed)
	if errors.Is(err, ErrExists) {
		return ErrCASLost
	}
	return err
}
