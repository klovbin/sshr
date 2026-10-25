package syncclient

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"sshr.dev/internal/hosts"
	"sshr.dev/internal/syncproto"
)

// memStore is an ObjectStore in memory with the create-only-if-absent
// write of S3 and WebDAV
type memStore struct {
	mu sync.Mutex
	m  map[string][]byte
	// beforeCreate runs before a Create, a test lets another device write
	// there
	beforeCreate func(name string)
}

func newMemStore() *memStore { return &memStore{m: map[string][]byte{}} }

func (s *memStore) Get(name string, max int) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.m[name]
	if !ok {
		return nil, ErrNotFound
	}
	if len(b) > max {
		return nil, ErrTooLarge
	}
	return append([]byte(nil), b...), nil
}

func (s *memStore) Put(name string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[name] = append([]byte(nil), data...)
	return nil
}

func (s *memStore) Create(name string, data []byte) error {
	if f := s.beforeCreate; f != nil {
		s.beforeCreate = nil
		f(name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[name]; ok {
		return ErrExists
	}
	s.m[name] = append([]byte(nil), data...)
	return nil
}

func (s *memStore) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, name)
	return nil
}

func (s *memStore) List(prefix string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k := range s.m {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

// objWorld is two devices that sync through one object store
func objWorld(t *testing.T) (store *memStore, a, b *Client) {
	useMemKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	store = newMemStore()
	mk := func(prefix string) *Client {
		return &Client{Store: &hosts.Store{Dir: t.TempDir()}, Dir: t.TempDir(), KeyPrefix: prefix,
			Backend: ObjectBackend{Store: store}, Log: &strings.Builder{}}
	}
	a, b = mk("a-"), mk("b-")
	_, err := a.Store.Add(hosts.Host{Name: "web", Host: "10.0.0.1", User: "u", PasswordMode: hosts.PasswordSaved, Password: "pw"})
	must(t, err)
	must(t, a.Init("memory", "laptop"))
	code, err := a.Invite()
	must(t, err)
	_, err = b.Join("memory", code, "desktop")
	must(t, err)
	pending, err := a.Pending()
	must(t, err)
	if len(pending) != 1 {
		t.Fatalf("pending %+v", pending)
	}
	_, err = a.Approve(pending[0].ID)
	must(t, err)
	must(t, b.Pull())
	return store, a, b
}

// two devices pair, sync both ways and the saved password arrives sealed
// for the other device (#128)
func TestObjectBackendSync(t *testing.T) {
	_, a, b := objWorld(t)
	list, _ := b.Store.List()
	if len(list) != 1 || list[0].Name != "web" {
		t.Fatalf("hosts on b %+v", list)
	}
	h := list[0]
	if err := hosts.UnlockSaved(&h); err != nil || h.Password != "pw" {
		t.Fatalf("password on b %q %v", h.Password, err)
	}
	_, err := b.Store.Add(hosts.Host{Name: "db", Host: "10.0.0.2", User: "u"})
	must(t, err)
	must(t, b.Push())
	must(t, a.Pull())
	if got, _ := a.Store.List(); len(got) != 2 {
		t.Fatalf("hosts on a %+v", got)
	}
	empty := ObjectBackend{Store: newMemStore()}
	if _, err := empty.Join([]byte(`{"device":{}}`)); err == nil {
		t.Error("joined a store without an account")
	}
}

// a device that loses the race to create the next manifest pulls and
// pushes again, the chain stays one line (#128)
func TestObjectBackendLostRace(t *testing.T) {
	store, a, b := objWorld(t)
	_, err := a.Store.Add(hosts.Host{Name: "a1", Host: "10.0.0.3", User: "u"})
	must(t, err)
	_, err = b.Store.Add(hosts.Host{Name: "b1", Host: "10.0.0.4", User: "u"})
	must(t, err)
	// b pushes in the moment a is about to create its manifest
	fired := false
	store.beforeCreate = func(name string) {
		if strings.HasPrefix(name, objManifests) {
			fired = true
			must(t, b.Push())
		}
	}
	must(t, a.Push())
	if !fired {
		t.Fatal("the race was not run, the first create of a was not a manifest")
	}
	must(t, b.Pull())
	for _, c := range []*Client{a, b} {
		got, _ := c.Store.List()
		if len(got) != 3 {
			t.Errorf("a device has %d hosts, want 3", len(got))
		}
	}
	ob := ObjectBackend{Store: store}
	all, _ := ob.manifests()
	for i, c := range all {
		if c != uint64(i+1) {
			t.Fatalf("manifest counters %v are not one line", all)
		}
	}
}

// removing a device takes its envelopes out and rotates the key, the
// device left over still reads nothing new (#128)
func TestObjectBackendRemoveDevice(t *testing.T) {
	store, a, b := objWorld(t)
	removed, err := a.RemoveDevice(b.st.DeviceID[:8])
	must(t, err)
	if removed.ID != b.st.DeviceID {
		t.Fatalf("removed %s", removed.ID)
	}
	if envs, _ := store.List(objEnvelopes + b.st.DeviceID); len(envs) != 0 {
		t.Errorf("envelopes of the removed device left: %v", envs)
	}
	if err := b.Pull(); err == nil {
		t.Error("the removed device pulled the new key")
	}
}

// a device reads the envelope of the epoch it asks for, a planted higher
// one does not hide it, an envelope that is there stays (#128, #227)
func TestObjectBackendEnvelopeEpochs(t *testing.T) {
	o := ObjectBackend{Store: newMemStore()}
	must(t, o.PutEnvelope(testDev, []byte(`{"epoch":2,"data":"AA=="}`)))
	must(t, o.Store.Put(envelopeName(testDev, 99), []byte(`{"epoch":99,"data":"garbage"}`)))
	b, err := o.GetEnvelope(testDev, 2)
	if err != nil || !strings.Contains(string(b), `"epoch":2`) {
		t.Fatalf("envelope of epoch 2: %s %v", b, err)
	}
	if err := o.PutEnvelope(testDev, []byte(`{"epoch":2,"data":"BB=="}`)); err != ErrStaleEpoch {
		t.Fatalf("second envelope of epoch 2 = %v", err)
	}
	if b, _ := o.GetEnvelope(testDev, 2); !strings.Contains(string(b), "AA==") {
		t.Errorf("the envelope of epoch 2 was replaced: %s", b)
	}
	// epoch 3 not delivered yet, the older one says the key is on its way
	if b, err := o.GetEnvelope(testDev, 3); err != nil || !strings.Contains(string(b), `"epoch":2`) {
		t.Errorf("envelope while epoch 3 is on its way: %s %v", b, err)
	}
	if _, err := o.GetEnvelope(strings.Repeat("e", 32), 1); err != ErrNotFound {
		t.Errorf("no envelope = %v", err)
	}
}

// a manifest stored under a newer name with the body of an older one ends
// the pull with an error, it does not loop (#224)
func TestManifestThatDoesNotMoveOn(t *testing.T) {
	store, a, b := objWorld(t)
	ob := ObjectBackend{Store: store}
	last, body, err := ob.Head()
	must(t, err)
	must(t, store.Put(manifestName(last+1), body))
	done := make(chan error, 1)
	go func() { done <- b.Pull() }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "again") {
			t.Fatalf("pull = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the pull loops on a manifest that does not move on")
	}
	_ = a
}

// objects bigger than their kind may be are refused on the way in and out,
// a store lists no more than an account holds (#226)
func TestObjectBackendLimits(t *testing.T) {
	store := newMemStore()
	o := ObjectBackend{Store: store}
	big := make([]byte, syncproto.MaxBlob+1)
	if err := o.PutBlob(testHash, big); err != ErrTooLarge {
		t.Errorf("big blob in = %v", err)
	}
	store.Put(objBlobs+testHash, big)
	if _, err := o.GetBlob(testHash); err != ErrTooLarge {
		t.Errorf("big blob out = %v", err)
	}
	store.Put(envelopeName(testDev, 1), make([]byte, maxSmall+1))
	if _, err := o.GetEnvelope(testDev, 1); err != ErrTooLarge {
		t.Errorf("big envelope = %v", err)
	}
	for i := 0; i <= maxNames; i++ {
		store.Put(fmt.Sprintf("%sx%06d", objDevices, i), []byte("{}"))
	}
	if _, err := o.Devices(); err == nil {
		t.Error("a store with more device objects than an account holds was listed")
	}
}

var (
	testDev  = strings.Repeat("d", 32)
	testHash = strings.Repeat("a", 64)
)

// names of a shape a sync account never writes are not used, a blob or a
// device named with ../ is refused (#229)
func TestObjectBackendNames(t *testing.T) {
	store := newMemStore()
	o := ObjectBackend{Store: store}
	store.Put("devices/../account", []byte(`{"id":"x"}`))
	store.Put(objManifests+"1", []byte("{}"))
	if b, err := o.Devices(); err != nil || string(b) != "[]" {
		t.Errorf("devices %s %v", b, err)
	}
	if _, _, err := o.Head(); err != ErrNotFound {
		t.Errorf("a manifest of another name shape was taken: %v", err)
	}
	if _, err := o.GetBlob("../account"); err == nil {
		t.Error("a blob named ../account was read")
	}
	if err := o.RemoveDevice("../x"); err == nil {
		t.Error("a device named ../x was removed")
	}
}

// a device record that does not parse or does not match its name and
// key is skipped, approvals go on (#228)
func TestObjectBackendBadDeviceRecords(t *testing.T) {
	store, a, _ := objWorld(t)
	store.Put(objDevices+strings.Repeat("b", 32), []byte("not json"))
	store.Put(objDevices+strings.Repeat("c", 32), []byte(`{"id":"`+a.st.DeviceID+`","active":false}`))
	pending, err := a.Pending()
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending %+v %v", pending, err)
	}
}

// a device joins only the account of its invite, a store that holds
// another account is refused (#230)
func TestJoinChecksTheAccount(t *testing.T) {
	_, a, _ := objWorld(t)
	code, err := a.Invite()
	must(t, err)
	other := newMemStore()
	other.Put(objAccount, []byte(strings.Repeat("f", 32)))
	c := &Client{Store: &hosts.Store{Dir: t.TempDir()}, Dir: t.TempDir(), KeyPrefix: "c-", Backend: ObjectBackend{Store: other}, Log: &strings.Builder{}}
	if _, err := c.Join("other", code, "x"); err == nil || !strings.Contains(err.Error(), "invite is for") {
		t.Fatalf("join into another account = %v", err)
	}
}

// a manifest for another account is not written into the store (#225)
func TestObjectBackendManifestAccount(t *testing.T) {
	store := newMemStore()
	store.Put(objAccount, []byte(strings.Repeat("a", 32)))
	o := ObjectBackend{Store: store}
	body := `{"version":1,"account":"` + strings.Repeat("b", 32) + `","epoch":1,"counter":1}`
	signed := fmt.Sprintf(`{"body":%q}`, base64Std(body))
	if err := o.PutManifest(0, []byte(signed)); err == nil || !strings.Contains(err.Error(), "another account") {
		t.Fatalf("manifest of another account = %v", err)
	}
}

func base64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// the store keeps the last keepHistory manifests, as sshr-sync does, so a
// busy account never passes maxNames (#246)
func TestObjectBackendKeepsHistory(t *testing.T) {
	store := newMemStore()
	must(t, store.Put(objAccount, []byte("acct")))
	o := ObjectBackend{Store: store}
	for n := uint64(1); n <= keepHistory+5; n++ {
		body, _ := json.Marshal(syncproto.Manifest{Account: "acct", Counter: n})
		signed, _ := json.Marshal(syncproto.Signed{Body: body})
		must(t, o.PutManifest(n-1, signed))
	}
	all, err := o.manifests()
	must(t, err)
	if len(all) != keepHistory || all[0] != 6 || all[len(all)-1] != keepHistory+5 {
		t.Fatalf("kept %d manifests, %d to %d", len(all), all[0], all[len(all)-1])
	}
	if c, _, err := o.Head(); err != nil || c != keepHistory+5 {
		t.Errorf("head %d %v", c, err)
	}
}

// a manifest with a counter far past the history does not make the
// store delete the real manifests (#247)
func TestObjectBackendTrimNeedsRealHistory(t *testing.T) {
	store := newMemStore()
	must(t, store.Put(objAccount, []byte("acct")))
	o := ObjectBackend{Store: store}
	put := func(n uint64) {
		t.Helper()
		body, _ := json.Marshal(syncproto.Manifest{Account: "acct", Counter: n})
		signed, _ := json.Marshal(syncproto.Signed{Body: body})
		must(t, o.PutManifest(n-1, signed))
	}
	for n := uint64(1); n <= 10; n++ {
		put(n)
	}
	const huge = 1_000_000_000
	must(t, store.Create(manifestName(huge-1), []byte("{}")))
	put(huge)
	all, err := o.manifests()
	must(t, err)
	if len(all) != 12 || all[0] != 1 {
		t.Errorf("the store kept %v", all)
	}
}

// a device whose next change is no longer kept is told it fell behind,
// a short history with a hole is still a server that skips changes (#248)
func TestFellBehindKeptHistory(t *testing.T) {
	store, a, b := objWorld(t)
	seen := b.st.Counter
	for i := 0; i < 3; i++ {
		_, err := a.Store.Add(hosts.Host{Name: fmt.Sprintf("h%d", i), Host: "10.0.0.9", User: "u"})
		must(t, err)
		must(t, a.Push())
	}
	must(t, store.Delete(manifestName(seen+1)))
	if err := b.Pull(); err == nil || !strings.Contains(err.Error(), "skipped changes") {
		t.Errorf("a hole in a short history: %v", err)
	}
	// a history as long as the store keeps, starting past this device
	head, _, err := a.backend().Head()
	must(t, err)
	for n := head + 1; n <= seen+keepHistory; n++ {
		body, _ := json.Marshal(syncproto.Manifest{Counter: n})
		signed, _ := json.Marshal(syncproto.Signed{Body: body})
		must(t, store.Create(manifestName(n), signed))
	}
	// unsigned padding is still a server that skips changes (#251)
	body, _ := json.Marshal(syncproto.Manifest{Counter: seen + keepHistory + 1})
	unsigned, _ := json.Marshal(syncproto.Signed{Body: body})
	must(t, store.Create(manifestName(seen+keepHistory+1), unsigned))
	if err := b.Pull(); err == nil || !strings.Contains(err.Error(), "skipped changes") {
		t.Errorf("unsigned padding: %v", err)
	}
	// the last change signed by a trusted device
	must(t, store.Delete(manifestName(seen+keepHistory+1)))
	body, _ = json.Marshal(syncproto.Manifest{Counter: seen + keepHistory + 1})
	sm := syncproto.Signed{Body: body, Signer: a.st.DeviceID, Sig: ed25519.Sign(a.keys.sign, signInput(body))}
	signed, _ := json.Marshal(sm)
	must(t, store.Create(manifestName(seen+keepHistory+1), signed))
	err = b.Pull()
	if err == nil || !strings.Contains(err.Error(), "keeps only the last") {
		t.Errorf("pull behind the kept history: %v", err)
	}
}

// countStore counts the bytes Get hands out
type countStore struct {
	*memStore
	read *int
}

func (s countStore) Get(name string, max int) ([]byte, error) {
	b, err := s.memStore.Get(name, max)
	*s.read += len(b)
	if err == ErrTooLarge {
		*s.read++
	}
	return b, err
}

// a push checks that the blobs are there without downloading them (#250)
func TestPutManifestDoesNotDownloadBlobs(t *testing.T) {
	store := newMemStore()
	must(t, store.Put(objAccount, []byte("acct")))
	hash := strings.Repeat("ab", 32)
	must(t, store.Put(objBlobs+hash, make([]byte, 50000)))
	read := 0
	o := ObjectBackend{Store: countStore{store, &read}}
	body, _ := json.Marshal(syncproto.Manifest{Account: "acct", Counter: 1, Entries: map[string]syncproto.Entry{"x": {Hash: hash}}})
	signed, _ := json.Marshal(syncproto.Signed{Body: body})
	must(t, o.PutManifest(0, signed))
	if read > 100 {
		t.Errorf("the push read %d bytes", read)
	}
	missing, _ := json.Marshal(syncproto.Manifest{Account: "acct", Counter: 2, Entries: map[string]syncproto.Entry{"y": {Hash: strings.Repeat("cd", 32)}}})
	signed, _ = json.Marshal(syncproto.Signed{Body: missing})
	if err := o.PutManifest(1, signed); err == nil {
		t.Error("a manifest with a missing blob went in")
	}
}

// blobLookups counts the blobs a push looks up
type blobLookups struct {
	*memStore
	n *int
}

func (s blobLookups) Get(name string, max int) ([]byte, error) {
	if strings.HasPrefix(name, objBlobs) {
		*s.n++
	}
	return s.memStore.Get(name, max)
}

// a push looks up only the blobs the previous manifest does not list,
// a blob that is new still has to be there
func TestPutManifestLooksUpNewBlobs(t *testing.T) {
	store := newMemStore()
	must(t, store.Put(objAccount, []byte("acct")))
	n := 0
	o := ObjectBackend{Store: blobLookups{store, &n}}
	entries := map[string]syncproto.Entry{}
	put := func(counter uint64) error {
		body, _ := json.Marshal(syncproto.Manifest{Account: "acct", Counter: counter, Entries: entries})
		signed, _ := json.Marshal(syncproto.Signed{Body: body})
		return o.PutManifest(counter-1, signed)
	}
	for i := range 20 {
		hash := fmt.Sprintf("%064x", i)
		must(t, store.Put(objBlobs+hash, []byte("x")))
		entries[fmt.Sprint(i)] = syncproto.Entry{Hash: hash}
	}
	must(t, put(1))
	if n != 20 {
		t.Fatalf("the first push looked up %d blobs of 20", n)
	}
	n = 0
	hash := fmt.Sprintf("%064x", 99)
	must(t, store.Put(objBlobs+hash, []byte("x")))
	entries["0"] = syncproto.Entry{Hash: hash}
	must(t, put(2))
	if n != 1 {
		t.Errorf("a push with one new blob looked up %d", n)
	}
	entries["1"] = syncproto.Entry{Hash: fmt.Sprintf("%064x", 100)}
	if err := put(3); err == nil {
		t.Error("a manifest with a missing new blob went in")
	}
	// a manifest planted under the name of change 2 with another counter
	// does not vouch for the blobs it lists
	planted, _ := json.Marshal(syncproto.Manifest{Account: "acct", Counter: 7, Entries: entries})
	signed, _ := json.Marshal(syncproto.Signed{Body: planted})
	must(t, store.Put(manifestName(2), signed))
	if err := put(3); err == nil {
		t.Error("a planted manifest let a missing blob in")
	}
}

// getCount counts the manifests a store hands out
type getCount struct {
	*memStore
	n *int
}

func (s getCount) Get(name string, max int) ([]byte, error) {
	if strings.HasPrefix(name, objManifests) {
		*s.n++
	}
	return s.memStore.Get(name, max)
}

// past a gap the client reads no more than it needs to judge (#252)
func TestGapStopsReading(t *testing.T) {
	store, a, b := objWorld(t)
	seen := b.st.Counter
	_, err := a.Store.Add(hosts.Host{Name: "h", Host: "10.0.0.9", User: "u"})
	must(t, err)
	must(t, a.Push())
	must(t, store.Delete(manifestName(seen+1)))
	for n := seen + 2; n <= seen+3*keepHistory; n++ {
		body, _ := json.Marshal(syncproto.Manifest{Counter: n})
		signed, _ := json.Marshal(syncproto.Signed{Body: body})
		must(t, store.Create(manifestName(n), signed))
	}
	got := 0
	b.Backend = ObjectBackend{Store: getCount{store, &got}}
	if err := b.Pull(); err == nil {
		t.Fatal("a padded history went through")
	}
	if got > keepHistory+manifestPage {
		t.Errorf("read %d manifests past the gap", got)
	}
}

// lockStore answers every create with ErrLocked, a WebDAV lock
type lockStore struct{ *memStore }

func (s lockStore) Create(string, []byte) error { return ErrLocked }

// a lock on the next manifest is a lost race, a lock on an envelope is an
// error and not a newer key the device already has (#257)
func TestLockedCreates(t *testing.T) {
	store := newMemStore()
	must(t, store.Put(objAccount, []byte("acct")))
	o := ObjectBackend{Store: lockStore{store}}
	body, _ := json.Marshal(syncproto.Manifest{Account: "acct", Counter: 1})
	signed, _ := json.Marshal(syncproto.Signed{Body: body})
	if err := o.PutManifest(0, signed); !errors.Is(err, ErrCASLost) {
		t.Errorf("locked manifest: %v", err)
	}
	env, _ := json.Marshal(syncproto.Envelope{Epoch: 2})
	if err := o.PutEnvelope(strings.Repeat("a", 32), env); err == nil || errors.Is(err, ErrStaleEpoch) {
		t.Errorf("locked envelope: %v", err)
	}
}

// a store that kept the change of another device under the number this
// device pushed is a fork, the device does not take it for its own change
// and says so (#128)
func TestForkIsSeen(t *testing.T) {
	store, a, b := objWorld(t)
	_, err := a.Store.Add(hosts.Host{Name: "from-a", Host: "10.0.0.3", User: "u"})
	must(t, err)
	must(t, a.Push())
	// a synced folder that has not brought the change of a to b yet
	var mine string
	for name := range store.m {
		if strings.HasPrefix(name, "manifests/") && (mine == "" || name > mine) {
			mine = name
		}
	}
	delete(store.m, mine)
	_, err = b.Store.Add(hosts.Host{Name: "from-b", Host: "10.0.0.4", User: "u"})
	must(t, err)
	must(t, b.Push())
	if err := a.Pull(); !errors.Is(err, ErrFork) {
		t.Fatalf("a pull after a fork: %v", err)
	}
}

// weakMemStore stands for a synced folder, a store whose create is not a
// compare and swap between devices
type weakMemStore struct{ *memStore }

func (weakMemStore) Conflicts() ([]string, error) { return nil, nil }

// on a store without a compare and swap a push the store did not keep is
// undone at the next pull, the change the store kept comes in and the
// edits of the losing device go out with its next push, nothing is lost
// (#128)
func TestForkIsUndone(t *testing.T) {
	store, a, b := objWorld(t)
	weak := ObjectBackend{Store: weakMemStore{store}}
	a.Backend, b.Backend = weak, weak
	_, err := a.Store.Add(hosts.Host{Name: "from-a", Host: "10.0.0.3", User: "u"})
	must(t, err)
	must(t, a.Push())
	var mine string
	for name := range store.m {
		if strings.HasPrefix(name, "manifests/") && (mine == "" || name > mine) {
			mine = name
		}
	}
	delete(store.m, mine)
	_, err = b.Store.Add(hosts.Host{Name: "from-b", Host: "10.0.0.4", User: "u"})
	must(t, err)
	must(t, b.Push())

	must(t, a.Pull())
	names := func(c *Client) map[string]bool {
		list, _ := c.Store.List()
		out := map[string]bool{}
		for _, h := range list {
			out[h.Name] = true
		}
		return out
	}
	if n := names(a); !n["from-a"] || !n["from-b"] {
		t.Fatalf("hosts on a after the fork %v", n)
	}
	must(t, a.Push())
	must(t, b.Pull())
	if n := names(b); !n["from-a"] || !n["from-b"] {
		t.Fatalf("hosts on b after a pushed again %v", n)
	}
	if a.st.Unconfirmed == nil {
		t.Error("the last push of a keeps no snapshot")
	}
	must(t, a.Pull())
	must(t, b.Push())
	_, err = b.Store.Add(hosts.Host{Name: "later", Host: "10.0.0.5", User: "u"})
	must(t, err)
	must(t, b.Push())
	must(t, a.Pull())
	if a.st.Unconfirmed != nil {
		t.Error("a change of b on top of the push of a left the snapshot")
	}
}

// both devices edit one host while the store keeps only the change of b,
// after the fork is undone no edit is lost, the host and a conflict copy
// carry both (#128)
func TestForkKeepsBothEditsOfOneHost(t *testing.T) {
	store, a, b := objWorld(t)
	weak := ObjectBackend{Store: weakMemStore{store}}
	a.Backend, b.Backend = weak, weak
	edit := func(c *Client, user string) {
		list, _ := c.Store.List()
		h := list[0]
		h.User = user
		_, err := c.Store.Update(h.ID, h)
		must(t, err)
	}
	edit(a, "user-a")
	must(t, a.Push())
	var mine string
	for name := range store.m {
		if strings.HasPrefix(name, "manifests/") && (mine == "" || name > mine) {
			mine = name
		}
	}
	delete(store.m, mine)
	edit(b, "user-b")
	must(t, b.Push())
	must(t, a.Pull())
	must(t, a.Push())
	must(t, b.Pull())
	for _, c := range []*Client{a, b} {
		users := map[string]bool{}
		list, _ := c.Store.List()
		for _, h := range list {
			users[h.User] = true
		}
		if !users["user-a"] || !users["user-b"] {
			t.Errorf("users on %s after the fork %v", c.KeyPrefix, users)
		}
	}
}

// forkWorld is a pair on a store without a compare and swap and a way to
// drop the newest changes of one device, as a sync tool that kept the
// other side does
func forkWorld(t *testing.T) (store *memStore, a, b *Client, drop func(n int)) {
	store, a, b = objWorld(t)
	weak := ObjectBackend{Store: weakMemStore{store}}
	a.Backend, b.Backend = weak, weak
	drop = func(n int) {
		for ; n > 0; n-- {
			var last string
			for name := range store.m {
				if strings.HasPrefix(name, "manifests/") && name > last {
					last = name
				}
			}
			delete(store.m, last)
		}
	}
	return store, a, b, drop
}

func hostNames(c *Client) map[string]bool {
	list, _ := c.Store.List()
	out := map[string]bool{}
	for _, h := range list {
		out[h.Name] = true
	}
	return out
}

// a pushed twice before it saw that the store kept the change of b under
// its first number, both pushes are undone, b pushed twice too, every
// edit ends on both devices
func TestForkAfterSeveralPushes(t *testing.T) {
	_, a, b, drop := forkWorld(t)
	for _, n := range []string{"a1", "a2"} {
		_, err := a.Store.Add(hosts.Host{Name: n, Host: "10.0.0.3", User: "u"})
		must(t, err)
		must(t, a.Push())
	}
	drop(2)
	for _, n := range []string{"b1", "b2"} {
		_, err := b.Store.Add(hosts.Host{Name: n, Host: "10.0.0.4", User: "u"})
		must(t, err)
		must(t, b.Push())
	}
	must(t, a.Pull())
	must(t, a.Push())
	must(t, b.Pull())
	for _, c := range []*Client{a, b} {
		n := hostNames(c)
		for _, want := range []string{"a1", "a2", "b1", "b2"} {
			if !n[want] {
				t.Errorf("%s misses %s: %v", c.KeyPrefix, want, n)
			}
		}
	}
}

// edits of two fields of one host on the two sides of a fork merge into
// the host, the version both started from is still kept
func TestForkMergesFieldsOfOneHost(t *testing.T) {
	_, a, b, drop := forkWorld(t)
	list, _ := a.Store.List()
	id := list[0].ID
	editHost(t, a, id, func(h *hosts.Host) { h.Name, h.Password = "web1", "" })
	must(t, a.Push())
	drop(1)
	editHost(t, b, id, func(h *hosts.Host) { h.Tags, h.Password = []string{"eu"}, "" })
	must(t, b.Push())
	must(t, a.Pull())
	h, err := a.Store.Find(id)
	must(t, err)
	if h.Name != "web1" || len(h.Tags) != 1 || h.Tags[0] != "eu" || conflictCopies(a) != 0 {
		t.Fatalf("host on a after the fork %+v, %d copies", h, conflictCopies(a))
	}
}
