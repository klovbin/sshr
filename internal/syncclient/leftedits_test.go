package syncclient

import (
	"os"
	"strings"
	"testing"

	"sshr.dev/internal/hosts"
	"sshr.dev/internal/vault"
)

// a device that leaves and joins the same account again keeps the edits it
// made since its last sync, an edit of another part of the same host on
// another device is merged in, a host removed here comes back and is not
// removed on the other devices (#382)
func TestLeaveAndJoinKeepsLocalEdits(t *testing.T) {
	store, a, b := objWorld(t)
	hs, err := a.Store.List()
	must(t, err)
	web := hs[0]
	added, err := a.Store.Add(hosts.Host{Name: "db", Host: "10.0.0.2", User: "u"})
	must(t, err)
	must(t, a.Push())
	must(t, b.Pull())

	// offline on b: a port on web and db removed
	h, err := b.Store.Find(web.ID)
	must(t, err)
	h.Port = 2222
	_, err = b.Store.Update(h.ID, *h)
	must(t, err)
	must(t, b.Store.Delete(added.ID))
	// meanwhile on a: a tag on web
	h, err = a.Store.Find(web.ID)
	must(t, err)
	h.Tags = []string{"prod"}
	_, err = a.Store.Update(h.ID, *h)
	must(t, err)
	must(t, a.Push())

	must(t, b.Leave(false))
	if _, err := os.Stat(b.leftEditsPath()); err != nil {
		t.Fatalf("leave kept no edits: %v", err)
	}
	c := inviteAgain(t, a, b, store)
	must(t, c.Pull())
	got, err := c.Store.Find(web.ID)
	must(t, err)
	if got.Port != 2222 || len(got.Tags) != 1 {
		t.Errorf("web after the join: port %d tags %q, want 2222 and prod\n%s", got.Port, got.Tags, c.Log)
	}
	if _, err := c.Store.Find(added.ID); err != nil {
		t.Errorf("db removed here did not come back: %v", err)
	}
	if _, err := os.Stat(c.leftEditsPath()); !os.IsNotExist(err) {
		t.Errorf("the kept edits outlived the join: %v", err)
	}
	must(t, c.Push())
	must(t, a.Pull())
	if h, _ := a.Store.Find(web.ID); h == nil || h.Port != 2222 {
		t.Errorf("a did not get the edit kept through the join: %+v", h)
	}
	if _, err := a.Store.Find(added.ID); err != nil {
		t.Errorf("db was removed on a: %v", err)
	}
}

// leave without --force stops when the hosts changed here cannot be told
// apart, the device key gone, and leaves the state as it was
func TestLeaveStopsWhenEditsCannotBeKept(t *testing.T) {
	_, _, b := objWorld(t)
	must(t, vault.SecretDelete(b.prefix()+"device"))
	if err := b.Leave(false); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("leave without the device key: %v", err)
	}
	if _, err := os.Stat(b.statePath()); err != nil {
		t.Errorf("the state is gone after a refused leave: %v", err)
	}
	must(t, b.Leave(true))
	if _, err := os.Stat(b.statePath()); !os.IsNotExist(err) {
		t.Errorf("leave --force kept the state: %v", err)
	}
}

// inviteAgain joins b to the account of a again under a new device key
func inviteAgain(t *testing.T, a, b *Client, store *memStore) *Client {
	t.Helper()
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
	return b
}
