package syncclient

import (
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
	store.beforeCreate = func(name string) {
		if strings.HasPrefix(name, objManifests) {
			must(t, b.Push())
		}
	}
	must(t, a.Push())
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
	must(t, o.PutEnvelope("d", []byte(`{"epoch":2,"data":"AA=="}`)))
	must(t, o.Store.Put(envelopeName("d", 99), []byte(`{"epoch":99,"data":"garbage"}`)))
	b, err := o.GetEnvelope("d", 2)
	if err != nil || !strings.Contains(string(b), `"epoch":2`) {
		t.Fatalf("envelope of epoch 2: %s %v", b, err)
	}
	if err := o.PutEnvelope("d", []byte(`{"epoch":2,"data":"BB=="}`)); err != ErrStaleEpoch {
		t.Fatalf("second envelope of epoch 2 = %v", err)
	}
	if b, _ := o.GetEnvelope("d", 2); !strings.Contains(string(b), "AA==") {
		t.Errorf("the envelope of epoch 2 was replaced: %s", b)
	}
	// epoch 3 not delivered yet, the older one says the key is on its way
	if b, err := o.GetEnvelope("d", 3); err != nil || !strings.Contains(string(b), `"epoch":2`) {
		t.Errorf("envelope while epoch 3 is on its way: %s %v", b, err)
	}
	if _, err := o.GetEnvelope("x", 1); err != ErrNotFound {
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
	if err := o.PutBlob("h", big); err != ErrTooLarge {
		t.Errorf("big blob in = %v", err)
	}
	store.Put(objBlobs+"h", big)
	if _, err := o.GetBlob("h"); err != ErrTooLarge {
		t.Errorf("big blob out = %v", err)
	}
	store.Put(envelopeName("d", 1), make([]byte, maxSmall+1))
	if _, err := o.GetEnvelope("d", 1); err != ErrTooLarge {
		t.Errorf("big envelope = %v", err)
	}
	for i := 0; i <= maxNames; i++ {
		store.Put(fmt.Sprintf("%sx%06d", objDevices, i), []byte("{}"))
	}
	if _, err := o.Devices(); err == nil {
		t.Error("a store with more device objects than an account holds was listed")
	}
}
