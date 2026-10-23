package syncserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"sshr.dev/internal/syncproto"
)

type client struct {
	t     *testing.T
	url   string
	token string
}

func (c *client) do(method, path string, body []byte, hdr map[string]string) (int, []byte, http.Header) {
	req, _ := http.NewRequest(method, c.url+path, bytes.NewReader(body))
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

func device(name string) syncproto.Device {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return syncproto.Device{ID: syncproto.DeviceID(pub), Name: name, SignPub: pub, KEMPub: []byte("kem")}
}

func manifest(account string, counter uint64, hashes ...string) []byte {
	m := syncproto.Manifest{Version: 1, Account: account, Counter: counter, Entries: map[string]syncproto.Entry{}}
	for i, h := range hashes {
		m.Entries[string(rune('a'+i))] = syncproto.Entry{Hash: h, Lamport: 1}
	}
	body, _ := json.Marshal(m)
	b, _ := json.Marshal(syncproto.Signed{Body: body})
	return b
}

func TestSyncServer(t *testing.T) {
	srv, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	anon := &client{t: t, url: ts.URL}

	d1 := device("laptop")
	body, _ := json.Marshal(syncproto.NewAccountRequest{Device: d1})
	code, b, _ := anon.do("POST", "/v1/accounts", body, nil)
	var tr syncproto.TokenResponse
	if code != 201 || json.Unmarshal(b, &tr) != nil {
		t.Fatalf("new account = %d %s", code, b)
	}
	a := "/v1/accounts/" + tr.Account
	c1 := &client{t: t, url: ts.URL, token: tr.Token}

	bad := d1
	bad.ID = "00000000000000000000000000000000"
	body, _ = json.Marshal(syncproto.NewAccountRequest{Device: bad})
	if code, _, _ := anon.do("POST", "/v1/accounts", body, nil); code != 400 {
		t.Errorf("device id not matching its key = %d", code)
	}
	body, _ = json.Marshal(syncproto.NewAccountRequest{Device: device("x\x1b[2Jy")})
	if code, _, _ := anon.do("POST", "/v1/accounts", body, nil); code != 400 {
		t.Errorf("escape in a device name = %d", code)
	}

	d2 := device("desktop")
	body, _ = json.Marshal(syncproto.NewAccountRequest{Device: d2})
	code, b, _ = anon.do("POST", a+"/join", body, nil)
	json.Unmarshal(b, &tr)
	c2 := &client{t: t, url: ts.URL, token: tr.Token}
	if code != 201 {
		t.Fatalf("join = %d %s", code, b)
	}
	if code, _, _ := c2.do("GET", a+"/manifest", nil, nil); code != 403 {
		t.Errorf("pending device read the manifest: %d", code)
	}
	if code, _, _ := (&client{t: t, url: ts.URL, token: "nope"}).do("GET", a+"/devices", nil, nil); code != 401 {
		t.Errorf("bad token = %d", code)
	}

	blob := []byte("ciphertext")
	sum := sha256.Sum256(blob)
	h := hex.EncodeToString(sum[:])
	if code, _, _ := c1.do("PUT", a+"/blobs/"+h, []byte("other"), nil); code != 400 {
		t.Errorf("blob with a wrong hash = %d", code)
	}
	if code, _, _ := c1.do("PUT", a+"/manifest", manifest(tr.Account, 1, h), map[string]string{"If-Match": "0"}); code != 409 {
		t.Errorf("manifest before its blob = %d", code)
	}
	if code, _, _ := c1.do("PUT", a+"/blobs/"+h, blob, nil); code != 204 {
		t.Fatalf("put blob = %d", code)
	}
	if code, b, _ := c1.do("PUT", a+"/manifest", manifest(tr.Account, 1, h), map[string]string{"If-Match": "0"}); code != 204 {
		t.Fatalf("first manifest = %d %s", code, b)
	}
	if code, _, _ := c1.do("PUT", a+"/manifest", manifest(tr.Account, 2, h), map[string]string{"If-Match": "0"}); code != 412 {
		t.Errorf("stale If-Match = %d", code)
	}
	if code, _, _ := c1.do("PUT", a+"/manifest", manifest(tr.Account, 5, h), map[string]string{"If-Match": "1"}); code != 400 {
		t.Errorf("counter jump = %d", code)
	}
	if code, _, hdr := c1.do("GET", a+"/manifest", nil, nil); code != 200 || hdr.Get("ETag") != "1" {
		t.Errorf("get manifest = %d etag %q", code, hdr.Get("ETag"))
	}

	if code, _, _ := c1.do("POST", a+"/devices/"+d2.ID+"/activate", nil, nil); code != 204 {
		t.Fatalf("activate = %d", code)
	}
	env, _ := json.Marshal(syncproto.Envelope{Epoch: 1, Data: []byte("sealed")})
	if code, _, _ := c1.do("PUT", a+"/envelopes/"+d2.ID, env, nil); code != 204 {
		t.Fatalf("put envelope = %d", code)
	}
	if code, b, _ := c2.do("GET", a+"/envelopes/"+d2.ID, nil, nil); code != 200 || !bytes.Contains(b, []byte(`"epoch":1`)) {
		t.Errorf("own envelope = %d %s", code, b)
	}
	if code, _, _ := c1.do("GET", a+"/envelopes/"+d2.ID, nil, nil); code != 403 {
		t.Errorf("read another device's envelope = %d", code)
	}
	newer, _ := json.Marshal(syncproto.Envelope{Epoch: 3, Data: []byte("sealed 3")})
	older, _ := json.Marshal(syncproto.Envelope{Epoch: 2, Data: []byte("sealed 2")})
	if code, _, _ := c1.do("PUT", a+"/envelopes/"+d2.ID, newer, nil); code != 204 {
		t.Errorf("put a newer envelope = %d", code)
	}
	if code, _, _ := c1.do("PUT", a+"/envelopes/"+d2.ID, older, nil); code != 409 {
		t.Errorf("put an older envelope over a newer one = %d", code)
	}
	if code, _, _ := c1.do("PUT", a+"/envelopes/"+d2.ID, newer, nil); code != 204 {
		t.Errorf("put the same epoch again = %d", code)
	}
	if code, b, _ := c2.do("GET", a+"/envelopes/"+d2.ID, nil, nil); code != 200 || !bytes.Contains(b, []byte(`"epoch":3`)) {
		t.Errorf("envelope after an older write = %d %s", code, b)
	}
	if code, b, _ := c2.do("GET", a+"/manifests?after=0", nil, nil); code != 200 || !bytes.Contains(b, []byte(`"body"`)) {
		t.Errorf("history = %d %s", code, b)
	}
	if code, _, _ := c1.do("DELETE", a+"/devices/"+d2.ID, nil, nil); code != 204 {
		t.Fatalf("remove device = %d", code)
	}
	if code, _, _ := c2.do("GET", a+"/manifest", nil, nil); code != 401 {
		t.Errorf("removed device still in = %d", code)
	}
}

func TestJoinLimitForgetsOldAddresses(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	for i := 0; i < 100; i++ {
		s.creates[fmt.Sprintf("10.0.0.%d", i)] = []time.Time{old}
	}
	r := httptest.NewRequest("POST", "/v1/accounts", nil)
	r.RemoteAddr = "192.0.2.1:5000"
	if !s.allowCreate(r) {
		t.Fatal("a new address was refused")
	}
	if len(s.creates) != 1 {
		t.Fatalf("%d addresses kept, want only the new one", len(s.creates))
	}
}

func TestJoinLimitBehindAProxy(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	req := func(xff string) *http.Request {
		r := httptest.NewRequest("POST", "/v1/accounts", nil)
		r.RemoteAddr = "127.0.0.1:40000"
		r.Header.Set("X-Forwarded-For", xff)
		return r
	}
	// without the option the proxy's own address counts for everyone
	if got := s.clientAddr(req("198.51.100.7")); got != "127.0.0.1" {
		t.Errorf("address without TrustProxy = %s", got)
	}
	s.TrustProxy = true
	for i := 0; i < 10; i++ {
		if !s.allowCreate(req("spoofed, 198.51.100.7")) {
			t.Fatal("refused before the limit")
		}
	}
	if s.allowCreate(req("198.51.100.7")) {
		t.Error("the same client got past the limit")
	}
	if !s.allowCreate(req("203.0.113.9")) {
		t.Error("another client behind the proxy was refused")
	}
	// a request that does not come over loopback keeps its own address
	r := req("203.0.113.9")
	r.RemoteAddr = "192.0.2.5:1234"
	if got := s.clientAddr(r); got != "192.0.2.5" {
		t.Errorf("address of a direct request = %s", got)
	}
}

// newAccount makes an account on a fresh server and returns its path and
// the client of its first device
func newAccount(t *testing.T) (*Server, *httptest.Server, string, *client) {
	t.Helper()
	srv, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// every request of a test comes from 127.0.0.1, X-Forwarded-For keeps
	// the join limit per test client
	srv.TrustProxy = true
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	body, _ := json.Marshal(syncproto.NewAccountRequest{Device: device("first")})
	code, b, _ := (&client{t: t, url: ts.URL}).do("POST", "/v1/accounts", body, map[string]string{"X-Forwarded-For": "192.0.2.1"})
	var tr syncproto.TokenResponse
	if code != 201 || json.Unmarshal(b, &tr) != nil {
		t.Fatalf("new account = %d %s", code, b)
	}
	return srv, ts, "/v1/accounts/" + tr.Account, &client{t: t, url: ts.URL, token: tr.Token}
}

func TestJoinLimits(t *testing.T) {
	_, ts, a, _ := newAccount(t)
	anon := &client{t: t, url: ts.URL}
	join := func(from string) int {
		body, _ := json.Marshal(syncproto.NewAccountRequest{Device: device("x")})
		code, _, _ := anon.do("POST", a+"/join", body, map[string]string{"X-Forwarded-For": from})
		return code
	}
	for i := 0; i < maxPending; i++ {
		if code := join(fmt.Sprintf("198.51.100.%d", i)); code != 201 {
			t.Fatalf("join %d = %d", i, code)
		}
	}
	if code := join("198.51.100.200"); code != 429 {
		t.Errorf("join past the pending limit = %d", code)
	}
	// one address gets 10 tries an hour
	_, ts, a, _ = newAccount(t)
	anon = &client{t: t, url: ts.URL}
	codes := map[int]int{}
	for i := 0; i < 11; i++ {
		codes[join("203.0.113.5")]++
	}
	if codes[429] == 0 {
		t.Errorf("one address was never limited: %v", codes)
	}
}

func TestRemoveUnknownDevice(t *testing.T) {
	_, _, a, c1 := newAccount(t)
	if code, _, _ := c1.do("DELETE", a+"/devices/"+device("x").ID, nil, nil); code != 404 {
		t.Errorf("remove an unknown device = %d", code)
	}
}

func TestWaitingDeviceRefusedEverywhere(t *testing.T) {
	_, ts, a, _ := newAccount(t)
	d := device("waiting")
	body, _ := json.Marshal(syncproto.NewAccountRequest{Device: d})
	code, b, _ := (&client{t: t, url: ts.URL}).do("POST", a+"/join", body, map[string]string{"X-Forwarded-For": "198.51.100.1"})
	var tr syncproto.TokenResponse
	if code != 201 || json.Unmarshal(b, &tr) != nil {
		t.Fatalf("join = %d %s", code, b)
	}
	c := &client{t: t, url: ts.URL, token: tr.Token}
	for _, r := range [][2]string{{"GET", "/devices"}, {"GET", "/manifest"}, {"GET", "/manifests?after=0"}, {"GET", "/envelopes/" + d.ID}, {"PUT", "/blobs/" + strings.Repeat("0", 64)}, {"PUT", "/manifest"}} {
		if code, _, _ := c.do(r[0], a+r[1], []byte("x"), nil); code != 403 {
			t.Errorf("%s %s by a waiting device = %d", r[0], r[1], code)
		}
	}
}

func TestOrphanBlobsKeptADay(t *testing.T) {
	srv, _, a, c1 := newAccount(t)
	put := func(data string) string {
		sum := sha256.Sum256([]byte(data))
		h := hex.EncodeToString(sum[:])
		if code, _, _ := c1.do("PUT", a+"/blobs/"+h, []byte(data), nil); code != 204 {
			t.Fatalf("put blob = %d", code)
		}
		return h
	}
	live, young, old := put("live"), put("young"), put("old")
	acc := strings.TrimPrefix(a, "/v1/accounts/")
	dir := filepath.Join(srv.accountDir(acc), "blobs")
	past := time.Now().Add(-25 * time.Hour)
	os.Chtimes(filepath.Join(dir, old), past, past)
	if code, b, _ := c1.do("PUT", a+"/manifest", manifest(acc, 1, live), map[string]string{"If-Match": "0"}); code != 204 {
		t.Fatalf("manifest = %d %s", code, b)
	}
	for h, want := range map[string]bool{live: true, young: true, old: false} {
		_, err := os.Stat(filepath.Join(dir, h))
		if (err == nil) != want {
			t.Errorf("blob %s kept = %v, want %v", h[:8], err == nil, want)
		}
	}
}

// /v1/health answers 200 while the data folder can be written, 503 when
// it cannot (#149)
func TestHealth(t *testing.T) {
	dir := t.TempDir()
	srv, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/health", nil))
	if rec.Code != 200 {
		t.Fatalf("health = %d %s", rec.Code, rec.Body)
	}
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		return
	}
	os.Chmod(dir, 0o500)
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/health", nil))
	if rec.Code != 503 {
		t.Fatalf("health of a read-only folder = %d", rec.Code)
	}
}
