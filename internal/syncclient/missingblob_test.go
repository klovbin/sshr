package syncclient

import (
	"bytes"
	"strings"
	"testing"

	"sshr.dev/internal/hosts"
)

// a blob the store lost leaves its host out of the pull, the other hosts
// still apply, a device that keeps the blob as its base puts it back
// (#384)
func TestMissingBlobDoesNotStopThePull(t *testing.T) {
	store, a, b := objWorld(t)
	hs, err := a.Store.List()
	must(t, err)
	web := hs[0]
	h, err := a.Store.Find(web.ID)
	must(t, err)
	h.Port = 2200
	_, err = a.Store.Update(web.ID, *h)
	must(t, err)
	added, err := a.Store.Add(hosts.Host{Name: "db", Host: "10.0.0.2", User: "u"})
	must(t, err)
	must(t, a.Push())
	lost := a.st.Entries[web.ID].Blob
	blob, err := store.Get(objBlobs+lost, 1<<20)
	must(t, err)
	must(t, store.Delete(objBlobs+lost))

	if err := b.Pull(); err != nil {
		t.Fatalf("a pull with one lost blob: %v", err)
	}
	if _, err := b.Store.Find(added.ID); err != nil {
		t.Errorf("the other host did not arrive: %v", err)
	}
	if h, _ := b.Store.Find(web.ID); h == nil || h.Port == 2200 {
		t.Errorf("web with a lost blob: %+v", h)
	}
	if !strings.Contains(b.Log.(*strings.Builder).String(), "lost the blob") {
		t.Errorf("no word about the lost blob:\n%s", b.Log)
	}

	// a keeps the blob it sealed as its base and puts it back on a fetch
	must(t, a.load())
	key, err := a.vaultKey(a.st.Epoch)
	must(t, err)
	if _, err := a.fetchBlob(web.ID, lost, key, a.st.Epoch); err != nil {
		t.Fatalf("a fetch on the device that keeps the blob: %v", err)
	}
	if got, err := store.Get(objBlobs+lost, 1<<20); err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("the blob is not back: %v", err)
	}
	// the skipped host is tried again with the next change of the account
	_, err = a.Store.Add(hosts.Host{Name: "cache", Host: "10.0.0.3", User: "u"})
	must(t, err)
	must(t, a.Push())
	must(t, b.Pull())
	if h, _ := b.Store.Find(web.ID); h == nil || h.Port != 2200 {
		t.Errorf("web after the blob came back: %+v", h)
	}
}

// a key change goes on when the store lost a blob this device never had,
// the entry goes on under the old key, the device does not keep the blob
// and cannot seal it again (#384)
func TestKeyChangeWithALostBlob(t *testing.T) {
	store, a, b := objWorld(t)
	hs, err := b.Store.List()
	must(t, err)
	h, err := b.Store.Find(hs[0].ID)
	must(t, err)
	h.Port = 2300
	_, err = b.Store.Update(h.ID, *h)
	must(t, err)
	must(t, b.Push())
	must(t, store.Delete(objBlobs+b.st.Entries[h.ID].Blob))
	must(t, a.Pull())
	if _, err := a.RemoveDevice(b.st.DeviceID[:8]); err != nil {
		t.Fatalf("a key change with a lost blob: %v", err)
	}
}

// a blob a push uploaded that a cleanup took before the manifest went in
// is put back right after it, the other devices read the host
func TestPushPutsBackItsBlob(t *testing.T) {
	store, a, b := objWorld(t)
	before, err := store.List(objBlobs)
	must(t, err)
	had := map[string]bool{}
	for _, n := range before {
		had[n] = true
	}
	store.beforeCreate = func(name string) {
		if !strings.HasPrefix(name, objManifests) {
			return
		}
		names, _ := store.List(objBlobs)
		for _, n := range names {
			if !had[n] {
				store.Delete(n)
			}
		}
	}
	hs, err := a.Store.List()
	must(t, err)
	h, err := a.Store.Find(hs[0].ID)
	must(t, err)
	h.Port = 2400
	_, err = a.Store.Update(h.ID, *h)
	must(t, err)
	must(t, a.Push())
	must(t, b.Pull())
	if got, _ := b.Store.Find(h.ID); got == nil || got.Port != 2400 {
		t.Fatalf("b after a push whose blob was taken: %+v\n%s", got, b.Log)
	}
}
