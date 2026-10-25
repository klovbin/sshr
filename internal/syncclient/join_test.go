package syncclient

import (
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	"sshr.dev/internal/hosts"
	"sshr.dev/internal/syncproto"
)

// manifestCounter counts the manifests read from the store
type manifestCounter struct {
	*memStore
	manifests atomic.Int64
}

func (s *manifestCounter) Get(name string, max int) ([]byte, error) {
	if strings.HasPrefix(name, objManifests) {
		s.manifests.Add(1)
	}
	return s.memStore.Get(name, max)
}

// pushEdits makes n changes on c, one push each
func pushEdits(t *testing.T, c *Client, n int) {
	t.Helper()
	hs, err := c.Store.List()
	must(t, err)
	for i := range n {
		h, err := c.Store.Find(hs[0].ID)
		must(t, err)
		h.Port = 1000 + i
		_, err = c.Store.Update(h.ID, *h)
		must(t, err)
		must(t, c.Push())
	}
}

// inviteThird makes device c on the store and has a approve it
func inviteThird(t *testing.T, a *Client, store ObjectStore) *Client {
	t.Helper()
	c := &Client{Store: &hosts.Store{Dir: t.TempDir()}, Dir: t.TempDir(), KeyPrefix: "c-",
		Backend: ObjectBackend{Store: store}, Log: &strings.Builder{}}
	code, err := a.Invite()
	must(t, err)
	_, err = c.Join("memory", code, "tablet")
	must(t, err)
	pending, err := a.Pending()
	must(t, err)
	if len(pending) != 1 {
		t.Fatalf("pending %+v", pending)
	}
	_, err = a.Approve(pending[0].ID)
	must(t, err)
	return c
}

// a device that joins a long history reads about one window of it and
// not the whole kept history
func TestJoinReadsTheEndOfHistory(t *testing.T) {
	store, a, _ := objWorld(t)
	pushEdits(t, a, joinWindow+joinWindow/2)
	cs := &manifestCounter{memStore: store}
	c := inviteThird(t, a, cs)
	cs.manifests.Store(0)
	must(t, c.Pull())
	if n := cs.manifests.Load(); n > joinWindow+5 {
		t.Errorf("the join read %d manifests of %d", n, joinWindow+joinWindow/2)
	}
	if h, err := c.Store.List(); err != nil || len(h) != 1 || h[0].Port != 1000+joinWindow+joinWindow/2-1 {
		t.Errorf("hosts on c %+v %v", h, err)
	}
}

// a device approved long before it first pulls steps back past the
// window to the change that added it
func TestJoinApprovedBeforeTheWindow(t *testing.T) {
	store, a, _ := objWorld(t)
	c := inviteThird(t, a, store)
	pushEdits(t, a, joinWindow+10)
	must(t, c.Pull())
	if h, err := c.Store.List(); err != nil || len(h) != 1 || h[0].Port != 1000+joinWindow+9 {
		t.Errorf("hosts on c %+v %v", h, err)
	}
}

// a newer change signed by another device of the account is not taken
// for the change that added this one, the change of the inviting device
// is
func TestJoinAnchorIsTheInvitingDevice(t *testing.T) {
	store, a, b := objWorld(t)
	c := inviteThird(t, a, store)
	n, forged := forgeManifest(t, b, func(*syncproto.Manifest) {})
	must(t, b.backend().PutManifest(n-1, forged))
	must(t, c.Pull())
	if c.st.Counter != n {
		t.Errorf("c is at change %d, the head is %d", c.st.Counter, n)
	}
}

// a head with a planted huge counter ends the join with an error and
// does not step back for ever
func TestJoinPlantedHugeHead(t *testing.T) {
	store, a, _ := objWorld(t)
	c := inviteThird(t, a, store)
	acct, err := store.Get(objAccount, 100)
	must(t, err)
	body, _ := json.Marshal(syncproto.Manifest{Account: string(acct), Counter: 1 << 62})
	signed, _ := json.Marshal(syncproto.Signed{Body: body})
	must(t, store.Put(manifestName(1<<62), signed))
	if err := c.Pull(); err == nil {
		t.Fatal("a join under a planted head went through")
	}
}
