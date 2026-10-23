package syncclient

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"sshr.dev/internal/syncproto"
)

// ObjectStore is a plain store of named objects, an S3 bucket or a WebDAV
// folder, it keeps one sync account, the one write a sync relies on is
// Create, which fails with ErrExists when the name is taken
type ObjectStore interface {
	// Get reads an object of at most max bytes, ErrNotFound when there is
	// none, ErrTooLarge for a bigger one, read no further than max+1
	Get(name string, max int) ([]byte, error)
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

// ErrTooLarge means an object is bigger than its kind may be, a store
// does not get to fill the memory of a device
var ErrTooLarge = errors.New("the object is too large")

// ObjectBackend runs a sync account in an ObjectStore: manifests are
// created as manifests/<counter> and a device that loses the race to
// create the next one pulls and tries again, as with sshr-sync, there is
// no server, so no token keeps a removed or waiting device out, the store
// credential does, see SECURITY.md
type ObjectBackend struct {
	Store ObjectStore
}

// Limits of what a store account holds, as sshr-sync has them
const (
	maxSmall     = 64 << 10 // the account, a device, an envelope
	maxNames     = 10000    // names one List may return
	manifestPage = 100      // manifests one ManifestsAfter returns
	maxPending   = 10       // devices waiting for approval
	// keepHistory is how many manifests stay, as sshr-sync keeps them, a
	// store that kept all would pass maxNames and stop the account
	keepHistory = 1000
)

const (
	objAccount   = "account"
	objDevices   = "devices/"
	objEnvelopes = "envelopes/"
	objBlobs     = "blobs/"
	objManifests = "manifests/"
)

// The shapes of the names in a store account, a name from List of any
// other shape is not used, a store cannot steer a read or a delete with
// ../ or a stray name
var (
	objIDRe       = regexp.MustCompile(`^[0-9a-f]{32}$`)
	objHashRe     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	objEpochRe    = regexp.MustCompile(`^[0-9]{10}$`)
	objCounterRe  = regexp.MustCompile(`^[0-9]{20}$`)
	errObjectName = errors.New("not a name of a sync account")
)

// checkID refuses a device id that is not 32 hex digits
func checkID(id string) error {
	if !objIDRe.MatchString(id) {
		return fmt.Errorf("%w: device %q", errObjectName, id)
	}
	return nil
}

// checkHash refuses a blob hash that is not 64 hex digits
func checkHash(hash string) error {
	if !objHashRe.MatchString(hash) {
		return fmt.Errorf("%w: blob %q", errObjectName, hash)
	}
	return nil
}

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
	account, err := o.Store.Get(objAccount, maxSmall)
	if errors.Is(err, ErrNotFound) {
		return nil, errors.New("the store holds no sync account")
	}
	if err != nil {
		return nil, err
	}
	if err := checkID(req.Device.ID); err != nil || syncproto.DeviceID(req.Device.SignPub) != req.Device.ID {
		return nil, errors.New("bad device")
	}
	b, err := o.Devices()
	if err != nil {
		return nil, err
	}
	var all []syncproto.DeviceRecord
	json.Unmarshal(b, &all)
	pending := 0
	for _, d := range all {
		if !d.Active {
			pending++
		}
	}
	if pending >= maxPending {
		return nil, errors.New("too many devices waiting for approval")
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
	names, err := o.list(objDevices)
	if err != nil {
		return nil, err
	}
	out := []syncproto.DeviceRecord{}
	for _, n := range names {
		if !objIDRe.MatchString(strings.TrimPrefix(n, objDevices)) {
			continue
		}
		b, err := o.Store.Get(n, maxSmall)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		// a record that does not parse, sits under another name or names
		// a key that is not its own is skipped, one bad object does not
		// stop approvals
		var rec syncproto.DeviceRecord
		if json.Unmarshal(b, &rec) != nil || objDevices+rec.ID != n || syncproto.DeviceID(rec.SignPub) != rec.ID {
			continue
		}
		out = append(out, rec)
	}
	return json.Marshal(out)
}

func (o ObjectBackend) Activate(id string) error {
	if err := checkID(id); err != nil {
		return err
	}
	b, err := o.Store.Get(objDevices+id, maxSmall)
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
	if err := checkID(id); err != nil {
		return err
	}
	if _, err := o.Store.Get(objDevices+id, maxSmall); err != nil {
		return err
	}
	envs, err := o.list(objEnvelopes + id + "/")
	if err != nil {
		return err
	}
	for _, n := range envs {
		if !objEpochRe.MatchString(strings.TrimPrefix(n, objEnvelopes+id+"/")) {
			continue
		}
		if err := o.Store.Delete(n); err != nil {
			return err
		}
	}
	return o.Store.Delete(objDevices + id)
}

// envelopes are the epochs of the envelopes of id
func (o ObjectBackend) envelopes(id string) ([]int, error) {
	names, err := o.list(objEnvelopes + id + "/")
	if err != nil {
		return nil, err
	}
	var out []int
	for _, n := range names {
		suffix := strings.TrimPrefix(n, objEnvelopes+id+"/")
		if !objEpochRe.MatchString(suffix) {
			continue
		}
		if e, err := strconv.Atoi(suffix); err == nil && e > 0 {
			out = append(out, e)
		}
	}
	return out, nil
}

// PutEnvelope keeps one envelope per epoch, an envelope of an epoch that
// is there already stays, a rotation delivers a new epoch, so a planted or
// older envelope never covers the one a device reads
func (o ObjectBackend) PutEnvelope(id string, env []byte) error {
	if err := checkID(id); err != nil {
		return err
	}
	var e syncproto.Envelope
	if err := json.Unmarshal(env, &e); err != nil {
		return err
	}
	if e.Epoch <= 0 {
		return fmt.Errorf("envelope of epoch %d", e.Epoch)
	}
	err := o.Store.Create(envelopeName(id, e.Epoch), env)
	if errors.Is(err, ErrExists) {
		return ErrStaleEpoch
	}
	return err
}

// GetEnvelope reads the envelope of epoch, a higher one someone planted is
// never taken for it, while it is missing the newest older one says the
// key is still on its way
func (o ObjectBackend) GetEnvelope(id string, epoch int) ([]byte, error) {
	if err := checkID(id); err != nil {
		return nil, err
	}
	b, err := o.Store.Get(envelopeName(id, epoch), maxSmall)
	if !errors.Is(err, ErrNotFound) {
		return b, err
	}
	epochs, err := o.envelopes(id)
	if err != nil {
		return nil, err
	}
	older := 0
	for _, e := range epochs {
		if e < epoch && e > older {
			older = e
		}
	}
	if older == 0 {
		return nil, ErrNotFound
	}
	return o.Store.Get(envelopeName(id, older), maxSmall)
}

func (o ObjectBackend) PutBlob(hash string, blob []byte) error {
	if err := checkHash(hash); err != nil {
		return err
	}
	if len(blob) > syncproto.MaxBlob {
		return ErrTooLarge
	}
	return o.Store.Put(objBlobs+hash, blob)
}

func (o ObjectBackend) GetBlob(hash string) ([]byte, error) {
	if err := checkHash(hash); err != nil {
		return nil, err
	}
	return o.Store.Get(objBlobs+hash, syncproto.MaxBlob)
}

// manifests are the counters of the stored manifests, in order
func (o ObjectBackend) manifests() ([]uint64, error) {
	names, err := o.list(objManifests)
	if err != nil {
		return nil, err
	}
	var out []uint64
	for _, n := range names {
		suffix := strings.TrimPrefix(n, objManifests)
		if !objCounterRe.MatchString(suffix) {
			continue
		}
		if c, err := strconv.ParseUint(suffix, 10, 64); err == nil {
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
	b, err := o.Store.Get(manifestName(last), syncproto.MaxManifest)
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
		b, err := o.Store.Get(manifestName(c), syncproto.MaxManifest)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
		if len(out) == manifestPage {
			break
		}
	}
	return json.Marshal(out)
}

// PutManifest creates manifests/<expect+1>, a device that created it first
// wins, every blob the manifest names has to be there, no server checks
// that here
func (o ObjectBackend) PutManifest(expect uint64, signed []byte) error {
	if len(signed) > syncproto.MaxManifest {
		return ErrTooLarge
	}
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
	account, err := o.Store.Get(objAccount, maxSmall)
	if err != nil {
		return err
	}
	if m.Account != string(account) {
		return errors.New("the manifest is for another account than the store holds")
	}
	for id, e := range m.Entries {
		if e.Hash == "" {
			continue
		}
		if err := checkHash(e.Hash); err != nil {
			return err
		}
		if _, err := o.Store.Get(objBlobs+e.Hash, syncproto.MaxBlob); err != nil {
			return fmt.Errorf("the blob of %s is not in the store: %v", short(id, 8), err)
		}
	}
	err = o.Store.Create(manifestName(m.Counter), signed)
	if errors.Is(err, ErrExists) {
		return ErrCASLost
	}
	if err != nil {
		return err
	}
	o.trimHistory(m.Counter)
	return nil
}

// trimHistory deletes the manifests more than keepHistory changes behind
// counter, only when the keepHistory manifests up to counter are all in
// the store, a planted manifest with a huge counter must not make the
// trim delete the real history, the push is already done, a delete that
// fails is tried again on the next push
func (o ObjectBackend) trimHistory(counter uint64) {
	if counter <= keepHistory {
		return
	}
	all, err := o.manifests()
	if err != nil {
		return
	}
	have := make(map[uint64]bool, len(all))
	for _, c := range all {
		have[c] = true
	}
	for c := counter - keepHistory + 1; c <= counter; c++ {
		if !have[c] {
			return
		}
	}
	for _, c := range all {
		if c > counter-keepHistory {
			break
		}
		o.Store.Delete(manifestName(c))
	}
}

// list names the objects under prefix, a store that lists more than an
// account can hold is refused
func (o ObjectBackend) list(prefix string) ([]string, error) {
	names, err := o.Store.List(prefix)
	if err != nil {
		return nil, err
	}
	if len(names) > maxNames {
		return nil, fmt.Errorf("the store lists %d objects under %s, more than a sync account holds", len(names), prefix)
	}
	return names, nil
}
