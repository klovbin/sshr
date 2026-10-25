package syncclient

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// editWeb makes n changes of the first host on c, one push each, every
// change leaves the blob before it to the history
func editWeb(t *testing.T, c *Client, n int) string {
	t.Helper()
	hs, err := c.Store.List()
	must(t, err)
	id := hs[0].ID
	for i := range n {
		h, err := c.Store.Find(id)
		must(t, err)
		h.Port = 3000 + i
		_, err = c.Store.Update(id, *h)
		must(t, err)
		must(t, c.Push())
	}
	return id
}

func blobCount(t *testing.T, s *memStore) int {
	t.Helper()
	names, err := s.List(objBlobs)
	must(t, err)
	return len(names)
}

// a blob goes only on a run a day after a run first saw it as an orphan,
// the blobs of the head and of the last changes stay, the other device
// still syncs
func TestCleanupDeletesOldOrphans(t *testing.T) {
	store, a, b := objWorld(t)
	id := editWeb(t, a, cleanupWindow+5)
	all := blobCount(t, store)
	now := time.Now()
	run := func(apply bool, at time.Time) CleanupReport {
		t.Helper()
		var r CleanupReport
		err := a.run(func() error {
			var err error
			r, err = a.cleanup(apply, at)
			return err
		})
		must(t, err)
		return r
	}
	first := run(true, now)
	if first.Orphans == 0 || first.Due != 0 || first.Deleted != 0 || blobCount(t, store) != all {
		t.Fatalf("a first run with --apply: %+v", first)
	}
	if r := run(true, now.Add(time.Hour)); r.Deleted != 0 {
		t.Fatalf("a run an hour later deleted %d", r.Deleted)
	}
	// a clock set back resets the journal
	if r := run(true, now.Add(-time.Hour)); r.Deleted != 0 {
		t.Fatalf("a run with the clock set back deleted %d", r.Deleted)
	}
	if r := run(false, now.Add(-time.Hour+cleanupGrace)); r.Due == 0 || r.Deleted != 0 || blobCount(t, store) != all {
		t.Fatalf("a dry run a day later: %+v", r)
	}
	r := run(true, now.Add(-time.Hour+cleanupGrace))
	if r.Deleted != first.Orphans || blobCount(t, store) != all-first.Orphans {
		t.Fatalf("a run a day later: %+v, %d blobs of %d left", r, blobCount(t, store), all)
	}
	if left := blobCount(t, store); left < cleanupWindow+1 {
		t.Errorf("only %d blobs left, the last %d changes need theirs", left, cleanupWindow+1)
	}
	must(t, b.Pull())
	if h, err := b.Store.Find(id); err != nil || h.Port != 3000+cleanupWindow+4 {
		t.Errorf("b after the cleanup: %+v %v", h, err)
	}
	editWeb(t, b, 1)
	must(t, a.Pull())
}

// a listing that misses a blob of the head deletes nothing
func TestCleanupRefusesAShortListing(t *testing.T) {
	store, a, _ := objWorld(t)
	editWeb(t, a, 3)
	for _, e := range a.st.Entries {
		must(t, store.Delete(objBlobs+e.Blob))
	}
	err := a.run(func() error {
		_, err := a.cleanup(true, time.Now())
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "misses the blob") {
		t.Fatalf("a listing without the head blobs: %v", err)
	}
}

// an account on sshr-sync is cleaned by the server
func TestCleanupOnTheServer(t *testing.T) {
	w := newWorld(t)
	w.pair()
	if _, err := w.a.Cleanup(true); !errors.Is(err, ErrServerCleans) {
		t.Fatalf("a cleanup on sshr-sync: %v", err)
	}
}

// deleteHook runs after the first Delete, a device that pushes while a
// cleanup deletes
type deleteHook struct {
	*memStore
	after func()
}

func (s *deleteHook) Delete(name string) error {
	err := s.memStore.Delete(name)
	if f := s.after; f != nil {
		s.after = nil
		f()
	}
	return err
}

// a name under blobs/ that is no hash is left alone, a change that shows
// up between two deletes stops the run
func TestCleanupStopsOnAChangeAndKeepsOtherNames(t *testing.T) {
	store, a, _ := objWorld(t)
	editWeb(t, a, cleanupWindow+3)
	must(t, store.Put(objBlobs+"sync-tool.tmp", []byte("x")))
	hook := &deleteHook{memStore: store}
	a.Backend = ObjectBackend{Store: hook}
	now := time.Now()
	run := func(at time.Time) (CleanupReport, error) {
		var r CleanupReport
		err := a.run(func() error {
			var err error
			r, err = a.cleanup(true, at)
			return err
		})
		return r, err
	}
	first, err := run(now)
	must(t, err)
	if first.Orphans < 2 {
		t.Fatalf("too few orphans for the test: %+v", first)
	}
	hook.after = func() { store.Put(manifestName(a.st.Counter+1), []byte("{}")) }
	r, err := run(now.Add(cleanupGrace))
	if err == nil || !strings.Contains(err.Error(), "changed during the cleanup") || r.Deleted != 1 {
		t.Fatalf("a change between two deletes: %+v %v", r, err)
	}
	must(t, store.Delete(manifestName(a.st.Counter+1)))
	r, err = run(now.Add(cleanupGrace))
	if err != nil || r.Deleted != first.Orphans-1 {
		t.Fatalf("the next run: %+v %v", r, err)
	}
	if _, err := store.Get(objBlobs+"sync-tool.tmp", 10); err != nil {
		t.Errorf("a name that is no blob was deleted: %v", err)
	}
}
