package syncclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"

	"sshr.dev/internal/app"
	"sshr.dev/internal/syncserver"
)

type world struct {
	t       *testing.T
	srv     *httptest.Server
	data    string
	a, b    *Client
	log     bytes.Buffer
	counter int
}

func newWorld(t *testing.T) *world {
	keyring.MockInit()
	data := t.TempDir()
	s, err := syncserver.New(data)
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, srv: httptest.NewServer(s), data: data}
	t.Cleanup(w.srv.Close)
	w.a = w.client("a-")
	w.b = w.client("b-")
	return w
}

func (w *world) client(prefix string) *Client {
	return &Client{Store: &app.Store{Dir: w.t.TempDir()}, Dir: w.t.TempDir(), KeyPrefix: prefix, Log: &w.log}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// pair sets up a with two hosts and joins b to it
func (w *world) pair() (web, db *app.Host) {
	t := w.t
	var err error
	web, err = w.a.Store.Add(app.Host{Name: "web", Host: "10.0.0.1", User: "u", PasswordMode: app.PasswordSaved, Password: " pw 1 "})
	must(t, err)
	db, err = w.a.Store.Add(app.Host{Name: "db", Host: "10.0.0.2", User: "u", Jump: "web"})
	must(t, err)
	must(t, w.a.Init(w.srv.URL, "laptop"))
	code, err := w.a.Invite()
	must(t, err)
	fp, err := w.b.Join(w.srv.URL, code, "desktop")
	must(t, err)
	if err := w.b.Pull(); err == nil || !strings.Contains(err.Error(), "waits for approval") {
		t.Fatalf("pull before approval = %v", err)
	}
	pending, err := w.a.Pending()
	must(t, err)
	if len(pending) != 1 || Fingerprint(pending[0].SignPub) != fp {
		t.Fatalf("pending = %+v, fingerprint on b %s", pending, fp)
	}
	_, err = w.a.Approve(pending[0].ID[:6])
	must(t, err)
	must(t, w.b.Pull())
	return web, db
}

func TestSyncTwoDevices(t *testing.T) {
	w := newWorld(t)
	web, _ := w.pair()
	got, err := w.b.Store.Find(web.ID)
	must(t, err)
	if got.Name != "web" {
		t.Fatalf("b has %+v", got)
	}
	must(t, app.Unlock(got))
	if got.Password != " pw 1 " {
		t.Errorf("password on b = %q", got.Password)
	}
	b, _ := os.ReadFile(filepath.Join(w.b.Store.Dir, web.ID+".json"))
	if strings.Contains(string(b), "pw 1") {
		t.Errorf("password in the clear on b:\n%s", b)
	}
	sa, _ := w.a.Status()
	sb, _ := w.b.Status()
	if sa.State != sb.State || sa.State == "" {
		t.Errorf("state fingerprints differ: %s %s", sa.State, sb.State)
	}

	// b edits, a sees it, a deletes, b sees it
	in := *got
	in.Port = 2222
	in.Password = ""
	_, err = w.b.Store.Update(web.ID, in)
	must(t, err)
	must(t, w.b.Push())
	must(t, w.a.Pull())
	if h, _ := w.a.Store.Find(web.ID); h.Port != 2222 {
		t.Errorf("a did not get the edit: %+v", h)
	}
	must(t, w.a.Store.Delete(web.ID))
	must(t, w.a.Push())
	must(t, w.b.Pull())
	if _, err := w.b.Store.Find(web.ID); err == nil {
		t.Error("b kept a host deleted on a")
	}
}

func TestSyncConflict(t *testing.T) {
	w := newWorld(t)
	_, db := w.pair()
	for i, c := range []*Client{w.a, w.b} {
		h, err := c.Store.Find(db.ID)
		must(t, err)
		h.Port = 3000 + i
		_, err = c.Store.Update(db.ID, *h)
		must(t, err)
	}
	must(t, w.a.Push())
	must(t, w.b.Push())
	must(t, w.a.Pull())
	ha, _ := w.a.Store.Find(db.ID)
	hb, _ := w.b.Store.Find(db.ID)
	if ha.Port != hb.Port {
		t.Errorf("devices disagree after a conflict: %d %d", ha.Port, hb.Port)
	}
	if !strings.Contains(w.log.String(), "conflict") {
		t.Errorf("no conflict reported:\n%s", w.log.String())
	}
	// the losing port is kept as a copy on both devices
	must(t, w.b.Push())
	must(t, w.a.Pull())
	for _, c := range []*Client{w.a, w.b} {
		hosts, _ := c.Store.List()
		ports := map[int]bool{}
		copies := 0
		for _, h := range hosts {
			ports[h.Port] = true
			if strings.Contains(h.Name, "(conflict ") {
				copies++
			}
		}
		if !ports[3000] || !ports[3001] || copies != 1 {
			t.Errorf("hosts after the conflict: %+v", hosts)
		}
	}
}

func TestConflictKeepsPasswordAndKey(t *testing.T) {
	w := newWorld(t)
	w.pair()
	h, err := w.a.Store.Add(app.Host{Name: "k", Host: "10.0.0.7", User: "u", KeyData: testKeyPEM(t)})
	must(t, err)
	cp, err := w.a.Store.Duplicate(h.ID, "k copy")
	must(t, err)
	if cp.ID == h.ID || cp.KeySealed == "" || cp.KeyPub != h.KeyPub {
		t.Errorf("duplicate = %+v", cp)
	}
	p, err := w.a.Store.Add(app.Host{Name: "p", Host: "10.0.0.8", User: "u", PasswordMode: app.PasswordSaved, Password: "pw x"})
	must(t, err)
	cp, err = w.a.Store.Duplicate(p.ID, "p copy")
	must(t, err)
	got, _ := w.a.Store.Find(cp.ID)
	must(t, app.Unlock(got))
	if got.Password != "pw x" {
		t.Errorf("duplicate password = %q", got.Password)
	}
}

func TestSyncVaultKeyStaysLocal(t *testing.T) {
	w := newWorld(t)
	w.pair()
	// a host with a key stored in sshr on a
	key := testKeyPEM(t)
	h, err := w.a.Store.Add(app.Host{Name: "k", Host: "10.0.0.3", User: "u", KeyData: key})
	must(t, err)
	must(t, w.a.Push())
	must(t, w.b.Pull())
	hb, err := w.b.Store.Find(h.ID)
	must(t, err)
	if hb.KeySealed != "" || hb.KeyPub != h.KeyPub {
		t.Errorf("b got %+v", hb)
	}
	hb.Port = 2200
	_, err = w.b.Store.Update(h.ID, *hb)
	must(t, err)
	must(t, w.b.Push())
	must(t, w.a.Pull())
	ha, _ := w.a.Store.Find(h.ID)
	if ha.Port != 2200 || ha.KeySealed == "" {
		t.Errorf("a lost its key or the edit: port %d sealed %q", ha.Port, ha.KeySealed)
	}
}

// manifestFiles lists the stored manifests of the only account
func (w *world) manifestDir() string {
	accounts, _ := os.ReadDir(filepath.Join(w.data, "accounts"))
	return filepath.Join(w.data, "accounts", accounts[0].Name(), "manifests")
}

func TestSyncDetectsServerTampering(t *testing.T) {
	w := newWorld(t)
	_, db := w.pair()
	dir := w.manifestDir()

	// a manifest changed on the server fails the signature check
	h, _ := w.a.Store.Find(db.ID)
	h.Port = 4000
	w.a.Store.Update(db.ID, *h)
	must(t, w.a.Push())
	n := len(mustRead(t, dir))
	last := filepath.Join(dir, fmt.Sprintf("%d.json", n))
	orig, _ := os.ReadFile(last)
	var sm struct {
		Body   []byte `json:"body"`
		MAC    []byte `json:"mac"`
		Signer string `json:"signer"`
		Sig    []byte `json:"sig"`
	}
	json.Unmarshal(orig, &sm)
	sm.Body = bytes.Replace(sm.Body, []byte(`"version":1`), []byte(`"version":1 `), 1)
	forged, _ := json.Marshal(sm)
	os.WriteFile(last, forged, 0o600)
	if err := w.b.Pull(); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Errorf("forged manifest = %v", err)
	}
	os.WriteFile(last, orig, 0o600)
	must(t, w.b.Pull())

	// a missing change in the history is a gap
	h.Port = 4001
	w.a.Store.Update(db.ID, *h)
	must(t, w.a.Push())
	h.Port = 4002
	w.a.Store.Update(db.ID, *h)
	must(t, w.a.Push())
	n = len(mustRead(t, dir))
	gap := filepath.Join(dir, fmt.Sprintf("%d.json", n-1))
	saved, _ := os.ReadFile(gap)
	os.Remove(gap)
	if err := w.b.Pull(); err == nil || !strings.Contains(err.Error(), "skipped") {
		t.Errorf("gap = %v", err)
	}
	os.WriteFile(gap, saved, 0o600)
	must(t, w.b.Pull())

	// the server going back to an older state is a rollback
	os.Remove(filepath.Join(dir, fmt.Sprintf("%d.json", n)))
	os.Remove(filepath.Join(dir, fmt.Sprintf("%d.json", n-1)))
	if err := w.b.Pull(); err == nil || !strings.Contains(err.Error(), "rolled") {
		t.Errorf("rollback = %v", err)
	}
}

func TestSyncRemoveDevice(t *testing.T) {
	w := newWorld(t)
	w.pair()
	sb, _ := w.b.Status()
	removed, err := w.a.RemoveDevice(sb.Device[:6])
	must(t, err)
	if removed.ID != sb.Device {
		t.Fatalf("removed %s", removed.ID)
	}
	if err := w.b.Pull(); err == nil {
		t.Error("removed device still pulls")
	}
	sa, _ := w.a.Status()
	if len(sa.Devices) != 1 {
		t.Errorf("devices after removal: %d", len(sa.Devices))
	}
	// a third device joins under the new key and gets every host
	c := w.client("c-")
	code, _ := w.a.Invite()
	_, err = c.Join(w.srv.URL, code, "phone")
	must(t, err)
	_, err = w.a.Approve(mustPending(t, w.a))
	must(t, err)
	must(t, c.Pull())
	hosts, _ := c.Store.List()
	if len(hosts) != 2 {
		t.Errorf("new device after rotation has %d hosts", len(hosts))
	}
}

func mustRead(t *testing.T, dir string) []os.DirEntry {
	es, err := os.ReadDir(dir)
	must(t, err)
	return es
}

func mustPending(t *testing.T, c *Client) string {
	p, err := c.Pending()
	must(t, err)
	if len(p) != 1 {
		t.Fatalf("pending = %d", len(p))
	}
	return p[0].ID
}

// a 1Password reference never comes from another device, a forged one
// would make this machine read the item and hand it to that host
func TestSyncOnePasswordRefsStayLocal(t *testing.T) {
	w := newWorld(t)
	w.pair()
	h, err := w.a.Store.Add(app.Host{Name: "op", Host: "10.0.0.9", User: "u", PasswordMode: app.PasswordOnePassword, PasswordRef: "op://Private/Bank/password"})
	must(t, err)
	must(t, w.a.Push())
	must(t, w.b.Pull())
	got, err := w.b.Store.Find(h.ID)
	must(t, err)
	if got.PasswordMode != app.PasswordAsk || got.PasswordRef != "" {
		t.Fatalf("b took the reference: mode %q ref %q", got.PasswordMode, got.PasswordRef)
	}
	if !strings.Contains(w.log.String(), "set its reference here") {
		t.Errorf("no note in the log:\n%s", w.log.String())
	}

	// b links its own item, a later edit from a keeps it
	in := *got
	in.PasswordMode, in.PasswordRef = app.PasswordOnePassword, "op://Mine/server/password"
	_, err = w.b.Store.Update(h.ID, in)
	must(t, err)
	must(t, w.b.Push())
	must(t, w.a.Pull())
	if ah, _ := w.a.Store.Find(h.ID); ah.PasswordRef != "op://Private/Bank/password" {
		t.Fatalf("b's reference reached a: %q", ah.PasswordRef)
	}
	ah, _ := w.a.Store.Find(h.ID)
	ain := *ah
	ain.Tags = []string{"edited"}
	_, err = w.a.Store.Update(h.ID, ain)
	must(t, err)
	must(t, w.a.Push())
	must(t, w.b.Pull())
	got, _ = w.b.Store.Find(h.ID)
	if !got.HasTag("edited") || got.PasswordRef != "op://Mine/server/password" {
		t.Fatalf("b after a's edit: tags %v ref %q", got.Tags, got.PasswordRef)
	}
	// a's move to another port drops the reference b set (#42)
	ah, _ = w.a.Store.Find(h.ID)
	ain = *ah
	ain.Port = 2200
	_, err = w.a.Store.Update(h.ID, ain)
	must(t, err)
	must(t, w.a.Push())
	must(t, w.b.Pull())
	got, _ = w.b.Store.Find(h.ID)
	if got.Port != 2200 || got.PasswordRef != "" || got.PasswordMode != app.PasswordAsk {
		t.Fatalf("b after a moved the host: port %d ref %q mode %q", got.Port, got.PasswordRef, got.PasswordMode)
	}

	// a forged payload with a reference, as an old or hostile client sends it
	forged := app.Host{ID: "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0", Name: "evil", Host: "attacker.example", User: "u",
		PasswordMode: app.PasswordOnePassword, PasswordRef: "op://Private/Bank/password",
		KeyMode: app.KeyOnePassword, KeyRef: "op://Private/key/private key", KeyPub: "ssh-ed25519 AAAA"}
	ev, err := w.b.Store.Import(forged)
	must(t, err)
	if ev.PasswordRef != "" || ev.KeyRef != "" || ev.KeyMode != "" {
		t.Fatalf("forged references kept: %+v", ev)
	}
}

func TestSyncWonConflictMakesOneCopy(t *testing.T) {
	w := newWorld(t)
	_, db := w.pair()
	for i, c := range []*Client{w.a, w.b} {
		h, err := c.Store.Find(db.ID)
		must(t, err)
		h.Port = 3000 + i
		_, err = c.Store.Update(db.ID, *h)
		must(t, err)
	}
	// the device with the smaller ID pushes first and loses, the other
	// one wins the conflict on pull and keeps pulling before it pushes
	x, y := w.a, w.b
	if x.st.DeviceID > y.st.DeviceID {
		x, y = y, x
	}
	must(t, x.Push())
	must(t, y.Pull())
	_, err := x.Store.Add(app.Host{Name: "other", Host: "10.0.0.9", User: "u"})
	must(t, err)
	must(t, x.Push())
	must(t, y.Pull())
	copies := func(c *Client) int {
		hosts, _ := c.Store.List()
		n := 0
		for _, h := range hosts {
			if strings.Contains(h.Name, "(conflict ") {
				n++
			}
		}
		return n
	}
	if n := copies(y); n != 1 {
		t.Fatalf("%d conflict copies of one conflict\n%s", n, w.log.String())
	}
	must(t, y.Push())
	must(t, x.Pull())
	hx, _ := x.Store.Find(db.ID)
	hy, _ := y.Store.Find(db.ID)
	if hx.Port != hy.Port || copies(x) != 1 {
		t.Fatalf("devices disagree after the push: ports %d %d, copies on x %d", hx.Port, hy.Port, copies(x))
	}
}

func TestSyncUnreadableHostIsNotDeleted(t *testing.T) {
	w := newWorld(t)
	_, db := w.pair()
	path := filepath.Join(w.b.Store.Dir, db.ID+".json")
	must(t, os.WriteFile(path, []byte("{broken"), 0o600))
	_, err := w.b.Store.Add(app.Host{Name: "other", Host: "10.0.0.9", User: "u"})
	must(t, err)
	must(t, w.b.Push())
	must(t, w.a.Pull())
	if _, err := w.a.Store.Find(db.ID); err != nil {
		t.Fatalf("a host file broken on b was deleted on a: %v\n%s", err, w.log.String())
	}
	if b, _ := os.ReadFile(path); string(b) != "{broken" {
		t.Fatal("the broken file was overwritten")
	}
	if !strings.Contains(w.log.String(), "does not load") {
		t.Errorf("no word about the broken file:\n%s", w.log.String())
	}
}

// writeRaw edits a host file behind the Store, the way a newer sshr would
// write a field this one does not know
func writeRaw(t *testing.T, s *app.Store, id string, edit func(map[string]any)) {
	t.Helper()
	path := filepath.Join(s.Dir, id+".json")
	b, err := os.ReadFile(path)
	must(t, err)
	var m map[string]any
	must(t, json.Unmarshal(b, &m))
	edit(m)
	b, err = json.Marshal(m)
	must(t, err)
	must(t, os.WriteFile(path, b, 0o600))
}

func TestSyncImportErrorSkipsOneHost(t *testing.T) {
	w := newWorld(t)
	web, db := w.pair()
	// db changes on both devices and b cannot take the version of a,
	// whichever side wins the conflict, web changes on a only
	h, err := w.b.Store.Find(db.ID)
	must(t, err)
	h.Port = 2201
	_, err = w.b.Store.Update(db.ID, *h)
	must(t, err)
	writeRaw(t, w.a.Store, db.ID, func(m map[string]any) { m["password_mode"] = "from-the-future"; m["port"] = 2202 })
	h, err = w.a.Store.Find(web.ID)
	must(t, err)
	h.Port = 2222
	_, err = w.a.Store.Update(web.ID, *h)
	must(t, err)
	must(t, w.a.Push())
	for i := 0; i < 2; i++ {
		must(t, w.b.Pull())
	}
	if h, _ := w.b.Store.Find(web.ID); h == nil || h.Port != 2222 {
		t.Fatalf("web did not sync past the host that failed: %+v\n%s", h, w.log.String())
	}
	hosts, _ := w.b.Store.List()
	for _, h := range hosts {
		if strings.Contains(h.Name, "(conflict ") {
			t.Fatalf("a copy was left for a host that was not imported: %s", h.Name)
		}
	}
	if !strings.Contains(w.log.String(), "skipped db") {
		t.Errorf("no word about the skipped host:\n%s", w.log.String())
	}
	// a push from b keeps the version of a on the server
	_, err = w.b.Store.Add(app.Host{Name: "other", Host: "10.0.0.9", User: "u"})
	must(t, err)
	must(t, w.b.Push())
	must(t, w.a.Pull())
	if h, _ := w.a.Store.Find(db.ID); h == nil || h.Port != 2202 {
		t.Fatalf("the push of b undid the change of a: %+v", h)
	}
}

func (w *world) join(c *Client) {
	code, err := w.a.Invite()
	must(w.t, err)
	_, err = c.Join(w.srv.URL, code, "x")
	must(w.t, err)
	pending, err := w.a.Pending()
	must(w.t, err)
	_, err = w.a.Approve(pending[0].ID)
	must(w.t, err)
	must(w.t, c.Pull())
}

func TestSyncTwoRotationsWhileOffline(t *testing.T) {
	w := newWorld(t)
	web, _ := w.pair()
	c := w.client("c-")
	d := w.client("d-")
	w.join(c)
	w.join(d)
	_, err := w.a.RemoveDevice(w.b.st.DeviceID[:8])
	must(t, err)
	_, err = w.a.RemoveDevice(d.st.DeviceID[:8])
	must(t, err)
	h, err := w.a.Store.Find(web.ID)
	must(t, err)
	h.Port = 2222
	_, err = w.a.Store.Update(web.ID, *h)
	must(t, err)
	must(t, w.a.Push())
	if err := c.Pull(); err != nil {
		t.Fatalf("device c after two rotations: %v", err)
	}
	if h, _ := c.Store.Find(web.ID); h == nil || h.Port != 2222 {
		t.Fatalf("change after the rotations not applied: %+v", h)
	}
}

// hookRT lets a test act on a request before it reaches the server, a
// non-nil response or error from before replaces the server's answer
type hookRT struct {
	before func(*http.Request) (*http.Response, error)
}

func (h hookRT) RoundTrip(r *http.Request) (*http.Response, error) {
	if resp, err := h.before(r); resp != nil || err != nil {
		return resp, err
	}
	return http.DefaultTransport.RoundTrip(r)
}

func answer(code int) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}}
}

func isManifestPut(r *http.Request) bool {
	return r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/manifest")
}

func isEnvelopePut(r *http.Request) bool {
	return r.Method == "PUT" && strings.Contains(r.URL.Path, "/envelopes/")
}

func TestRemoveDeviceRetriesALostRace(t *testing.T) {
	w := newWorld(t)
	web, _ := w.pair()
	c := w.client("c-")
	w.join(c)
	raced, committed := false, false
	envelopesBefore := 0
	w.a.HTTP = &http.Client{Transport: hookRT{func(r *http.Request) (*http.Response, error) {
		switch {
		case isManifestPut(r) && !raced:
			// b pushes first, the manifest of a loses
			raced = true
			h, err := w.b.Store.Find(web.ID)
			must(t, err)
			h.Port = 2222
			_, err = w.b.Store.Update(web.ID, *h)
			must(t, err)
			must(t, w.b.Push())
		case isManifestPut(r):
			committed = true
		case isEnvelopePut(r) && !committed:
			envelopesBefore++
		}
		return nil, nil
	}}}
	if _, err := w.a.RemoveDevice(c.st.DeviceID[:8]); err != nil {
		t.Fatalf("remove after a lost race: %v\n%s", err, w.log.String())
	}
	if envelopesBefore != 0 {
		t.Errorf("%d envelopes written before the manifest won", envelopesBefore)
	}
	for _, d := range w.a.st.Trusted {
		if d.ID == c.st.DeviceID {
			t.Fatal("the removed device is still trusted")
		}
	}
	if w.a.st.Epoch != 2 || w.a.st.Rotation != nil {
		t.Fatalf("epoch %d, rotation %+v", w.a.st.Epoch, w.a.st.Rotation)
	}
	must(t, w.b.Pull())
	if w.b.st.Epoch != 2 {
		t.Fatalf("b is on epoch %d", w.b.st.Epoch)
	}
	if h, _ := w.a.Store.Find(web.ID); h == nil || h.Port != 2222 {
		t.Fatalf("the change of b was lost: %+v", h)
	}
	if strings.Contains(w.log.String(), "conflict") {
		t.Fatalf("the retry made conflicts:\n%s", w.log.String())
	}
}

func TestRemoveDeviceGivesUpCleanly(t *testing.T) {
	w := newWorld(t)
	w.pair()
	c := w.client("c-")
	w.join(c)
	w.a.HTTP = &http.Client{Transport: hookRT{func(r *http.Request) (*http.Response, error) {
		switch {
		case isManifestPut(r):
			return answer(http.StatusPreconditionFailed), nil
		case isEnvelopePut(r):
			t.Error("an envelope was written though no manifest won")
		}
		return nil, nil
	}}}
	if _, err := w.a.RemoveDevice(c.st.DeviceID[:8]); err == nil {
		t.Fatal("remove reported success though every push lost")
	}
	if w.a.st.Epoch != 1 || w.a.st.Rotation != nil {
		t.Fatalf("epoch %d, rotation %+v", w.a.st.Epoch, w.a.st.Rotation)
	}
	if _, ok, _ := app.SecretGet(w.a.prefix() + "key-pending"); ok {
		t.Error("key-pending left in the keychain")
	}
	w.a.HTTP = nil
	must(t, w.a.Pull())
	must(t, c.Pull())
}

func TestRemoveDeviceFinishesAfterACrash(t *testing.T) {
	w := newWorld(t)
	w.pair()
	c := w.client("c-")
	w.join(c)
	committed := false
	w.a.HTTP = &http.Client{Transport: hookRT{func(r *http.Request) (*http.Response, error) {
		if isManifestPut(r) {
			committed = true
		}
		if committed && isEnvelopePut(r) {
			return nil, errors.New("cut off")
		}
		return nil, nil
	}}}
	if _, err := w.a.RemoveDevice(c.st.DeviceID[:8]); err == nil || !strings.Contains(err.Error(), "not delivered") {
		t.Fatalf("remove with no envelope delivered = %v", err)
	}
	if err := w.b.Pull(); !errors.Is(err, ErrKeyPending) {
		t.Fatalf("b before the key arrives = %v", err)
	}
	w.a.HTTP = nil
	must(t, w.a.Pull())
	must(t, w.b.Pull())
	if w.b.st.Epoch != 2 {
		t.Fatalf("b is on epoch %d", w.b.st.Epoch)
	}
	if _, ok, _ := app.SecretGet(w.a.prefix() + "key-pending"); ok {
		t.Error("key-pending left in the keychain")
	}
}

func TestApproveDoesNotBringBackARemovedDevice(t *testing.T) {
	w := newWorld(t)
	w.pair()
	c := w.client("c-")
	w.join(c)
	d := w.client("d-")
	code, err := w.a.Invite()
	must(t, err)
	_, err = d.Join(w.srv.URL, code, "d")
	must(t, err)
	pending, err := w.a.Pending()
	must(t, err)
	raced := false
	w.a.HTTP = &http.Client{Transport: hookRT{func(r *http.Request) (*http.Response, error) {
		if isManifestPut(r) && !raced {
			// b removes c and changes the key just before a pushes
			raced = true
			_, err := w.b.RemoveDevice(c.st.DeviceID[:8])
			must(t, err)
		}
		return nil, nil
	}}}
	_, err = w.a.Approve(pending[0].ID)
	must(t, err)
	for _, x := range w.a.st.Trusted {
		if x.ID == c.st.DeviceID {
			t.Fatal("approve wrote the removed device back")
		}
	}
	must(t, d.Pull())
	if d.st.Epoch != w.a.st.Epoch || d.st.Epoch != 2 {
		t.Fatalf("d is on epoch %d, a on %d", d.st.Epoch, w.a.st.Epoch)
	}
}

func TestSyncRotationResealsCarriedEntries(t *testing.T) {
	w := newWorld(t)
	web, db := w.pair()
	c := w.client("c-")
	w.join(c)
	// b cannot load db, it still carries the entry when it changes the key
	must(t, os.WriteFile(filepath.Join(w.b.Store.Dir, db.ID+".json"), []byte("{broken"), 0o600))
	_, err := w.b.RemoveDevice(c.st.DeviceID[:8])
	must(t, err)
	must(t, w.a.Pull())
	// a device joining now reads every entry with the new key only
	d := w.client("d-")
	w.join(d)
	for _, id := range []string{web.ID, db.ID} {
		if _, err := d.Store.Find(id); err != nil {
			t.Fatalf("host %s lost: %v", id[:8], err)
		}
	}
}

func TestSyncRotationResealsSkippedEntries(t *testing.T) {
	w := newWorld(t)
	_, db := w.pair()
	c := w.client("c-")
	w.join(c)
	// a writes a db that b cannot import, b carries it as skipped
	writeRaw(t, w.a.Store, db.ID, func(m map[string]any) { m["password_mode"] = "from-the-future" })
	must(t, w.a.Push())
	must(t, w.b.Pull())
	if _, ok := w.b.st.Skipped[db.ID]; !ok {
		t.Fatal("db is not skipped on b")
	}
	_, err := w.b.RemoveDevice(c.st.DeviceID[:8])
	must(t, err)
	must(t, w.a.Pull())
	d := w.client("d-")
	w.join(d)
	if !strings.Contains(w.log.String(), "skipped db") {
		t.Fatalf("d did not reach the entry:\n%s", w.log.String())
	}
}

func TestSyncReplacesAWrongCachedKey(t *testing.T) {
	w := newWorld(t)
	web, _ := w.pair()
	name := w.b.prefix() + "key-1"
	good, _, err := app.SecretGet(name)
	must(t, err)
	must(t, app.SecretSet(name, bytes.Repeat([]byte{7}, 32)))
	h, err := w.a.Store.Find(web.ID)
	must(t, err)
	h.Port = 2222
	_, err = w.a.Store.Update(web.ID, *h)
	must(t, err)
	must(t, w.a.Push())
	if err := w.b.Pull(); err != nil {
		t.Fatalf("pull with a wrong cached key: %v", err)
	}
	if got, _, _ := app.SecretGet(name); !bytes.Equal(got, good) {
		t.Error("the wrong key is still cached")
	}
}
