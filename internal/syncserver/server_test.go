package syncserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

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
