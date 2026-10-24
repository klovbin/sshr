package syncclient

import (
	"os"
	"slices"
	"strings"
	"testing"

	"sshr.dev/internal/hosts"
)

// editHost changes host id on c through the store, as the app would
func editHost(t *testing.T, c *Client, id string, edit func(*hosts.Host)) {
	t.Helper()
	h, err := c.Store.Find(id)
	must(t, err)
	edit(h)
	_, err = c.Store.Update(id, *h)
	must(t, err)
}

func conflictCopies(c *Client) int {
	list, _ := c.Store.List()
	n := 0
	for _, h := range list {
		if strings.Contains(h.Name, "(conflict ") {
			n++
		}
	}
	return n
}

// TestSyncMergesFields checks that a rename on one device and a tag on the
// other give one host with both on each device, no copy, and that later
// syncs push nothing (#152)
func TestSyncMergesFields(t *testing.T) {
	w := newWorld(t)
	web, _ := w.pair()
	editHost(t, w.a, web.ID, func(h *hosts.Host) { h.Name, h.Password = "web1", "" })
	editHost(t, w.b, web.ID, func(h *hosts.Host) { h.Tags, h.Password = []string{"eu"}, "" })
	must(t, w.a.Push())
	must(t, w.b.Push())
	must(t, w.a.Pull())
	for _, c := range []*Client{w.a, w.b} {
		h, err := c.Store.Find(web.ID)
		must(t, err)
		if h.Name != "web1" || !slices.Equal(h.Tags, []string{"eu"}) {
			t.Errorf("host after the merge: %+v", h)
		}
		must(t, hosts.UnlockSaved(h))
		if h.Password != " pw 1 " {
			t.Errorf("password after the merge = %q", h.Password)
		}
		if n := conflictCopies(c); n != 0 {
			t.Errorf("%d conflict copies\n%s", n, w.log.String())
		}
	}
	if !strings.Contains(w.log.String(), "merged the changes") {
		t.Errorf("no merge reported:\n%s", w.log.String())
	}
	counter := w.a.st.Counter
	must(t, w.a.Push())
	must(t, w.b.Push())
	must(t, w.a.Pull())
	if w.a.st.Counter != counter || w.b.st.Counter != counter {
		t.Errorf("syncs after the merge pushed again: %d -> %d %d", counter, w.a.st.Counter, w.b.st.Counter)
	}
}

// TestSyncMergeKeepsPasswordWithItsAddress checks that a new password on
// one device and a new address on the other are not merged, the password
// must not go to the address the other device chose
func TestSyncMergeKeepsPasswordWithItsAddress(t *testing.T) {
	w := newWorld(t)
	web, _ := w.pair()
	editHost(t, w.a, web.ID, func(h *hosts.Host) { h.Password = "new pw" })
	editHost(t, w.b, web.ID, func(h *hosts.Host) { h.Host, h.Password = "10.0.0.5", "" })
	must(t, w.a.Push())
	must(t, w.b.Push())
	if n := conflictCopies(w.b); n != 1 {
		t.Fatalf("%d conflict copies, want 1\n%s", n, w.log.String())
	}
}

// TestSyncMergeAfterKeyRotation checks that a key rotation by another
// device, which changes the blob of every host without changing the host,
// keeps the base, a later edit on both sides still merges (#285)
func TestSyncMergeAfterKeyRotation(t *testing.T) {
	w := newWorld(t)
	web, _ := w.pair()
	c := w.client("c-")
	w.join(c)
	must(t, w.b.Pull())
	editHost(t, w.b, web.ID, func(h *hosts.Host) { h.Tags, h.Password = []string{"eu"}, "" })
	_, err := w.a.RemoveDevice(c.st.DeviceID[:8])
	must(t, err)
	must(t, w.b.Pull())
	editHost(t, w.a, web.ID, func(h *hosts.Host) { h.Name, h.Password = "web1", "" })
	must(t, w.a.Push())
	must(t, w.b.Push())
	h, err := w.b.Store.Find(web.ID)
	must(t, err)
	if h.Name != "web1" || !slices.Equal(h.Tags, []string{"eu"}) || conflictCopies(w.b) != 0 {
		t.Fatalf("host after a rotation and a merge: %+v, %d copies\n%s", h, conflictCopies(w.b), w.log.String())
	}
}

// TestSyncMergeWithoutBase checks that a host whose synced version is not
// kept here falls back to a conflict copy
func TestSyncMergeWithoutBase(t *testing.T) {
	w := newWorld(t)
	web, _ := w.pair()
	editHost(t, w.a, web.ID, func(h *hosts.Host) { h.Name, h.Password = "web1", "" })
	editHost(t, w.b, web.ID, func(h *hosts.Host) { h.Tags, h.Password = []string{"eu"}, "" })
	must(t, os.RemoveAll(w.b.baseDir()))
	must(t, w.a.Push())
	must(t, w.b.Push())
	if n := conflictCopies(w.b); n != 1 {
		t.Fatalf("%d conflict copies, want 1\n%s", n, w.log.String())
	}
}
