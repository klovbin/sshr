package s3store

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"sshr.dev/internal/hosts"
	"sshr.dev/internal/syncclient"
	"sshr.dev/internal/vault"
)

// fakeS3 answers the path-style requests of the SDK the way S3 does, a
// PUT with If-None-Match: * fails with 412 when the key is there
type fakeS3 struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if bucket != "sshr" {
		http.Error(w, "<Error><Code>NoSuchBucket</Code></Error>", http.StatusNotFound)
		return
	}
	switch {
	case r.Method == "GET" && key == "":
		type content struct{ Key string }
		var res struct {
			XMLName     xml.Name  `xml:"ListBucketResult"`
			IsTruncated bool      `xml:"IsTruncated"`
			Contents    []content `xml:"Contents"`
		}
		var keys []string
		for k := range f.m {
			if strings.HasPrefix(k, r.URL.Query().Get("prefix")) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			res.Contents = append(res.Contents, content{k})
		}
		w.Header().Set("Content-Type", "application/xml")
		xml.NewEncoder(w).Encode(res)
	case r.Method == "GET":
		b, ok := f.m[key]
		if !ok {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, "<Error><Code>NoSuchKey</Code></Error>")
			return
		}
		w.Write(b)
	case r.Method == "PUT":
		if _, ok := f.m[key]; ok && r.Header.Get("If-None-Match") == "*" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusPreconditionFailed)
			io.WriteString(w, "<Error><Code>PreconditionFailed</Code></Error>")
			return
		}
		b, _ := io.ReadAll(r.Body)
		f.m[key] = b
		w.Header().Set("ETag", `"x"`)
	case r.Method == "DELETE":
		delete(f.m, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func newStore(t *testing.T) (*Store, *fakeS3) {
	t.Helper()
	f := &fakeS3{m: map[string][]byte{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	s, err := New(Config{Endpoint: srv.URL, Bucket: "sshr", Prefix: "acct", KeyID: "id"}, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	return s, f
}

// get, put, create, delete and list behave as syncclient.ObjectStore
// needs, a second create of a name fails (#128)
func TestStoreObjects(t *testing.T) {
	s, f := newStore(t)
	if _, err := s.Get("x", 10); err != syncclient.ErrNotFound {
		t.Fatalf("missing = %v", err)
	}
	if err := s.Create("manifests/1", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := s.Create("manifests/1", []byte("two")); err != syncclient.ErrExists {
		t.Fatalf("second create = %v", err)
	}
	if b, err := s.Get("manifests/1", 10); err != nil || string(b) != "one" {
		t.Fatalf("get %q %v", b, err)
	}
	if _, err := s.Get("manifests/1", 2); err != syncclient.ErrTooLarge {
		t.Fatalf("too large = %v", err)
	}
	if _, ok := f.m["acct/manifests/1"]; !ok {
		t.Fatalf("keys %v, the prefix is missing", f.m)
	}
	must(t, s.Put("blobs/a", []byte("b")))
	names, err := s.List("blobs/")
	if err != nil || len(names) != 1 || names[0] != "blobs/a" {
		t.Fatalf("list %v %v", names, err)
	}
	must(t, s.Delete("blobs/a"))
	must(t, s.Delete("blobs/a"))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// memKeychain keeps secrets in memory, the test never reaches the system
// keychain
type memKeychain struct {
	mu sync.Mutex
	m  map[string]string
}

func (k *memKeychain) Get(n string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.m[n]
	if !ok {
		return "", vault.ErrSecretNotFound
	}
	return v, nil
}
func (k *memKeychain) Set(n, v string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.m[n] = v
	return nil
}
func (k *memKeychain) Delete(n string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.m, n)
	return nil
}

// two devices pair and sync through a bucket (#128)
func TestSyncThroughBucket(t *testing.T) {
	vault.SetKeychain(&memKeychain{m: map[string]string{}})
	vault.ResetForTest(filepath.Join(t.TempDir(), ".lock"))
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	s, _ := newStore(t)
	mk := func(p string) *syncclient.Client {
		return &syncclient.Client{Store: &hosts.Store{Dir: t.TempDir()}, Dir: t.TempDir(), KeyPrefix: p,
			Backend: syncclient.ObjectBackend{Store: s}, Log: io.Discard}
	}
	a, b := mk("a-"), mk("b-")
	_, err := a.Store.Add(hosts.Host{Name: "web", Host: "10.0.0.1", User: "u"})
	must(t, err)
	must(t, a.Init("s3", "laptop"))
	code, err := a.Invite()
	must(t, err)
	_, err = b.Join("s3", code, "desktop")
	must(t, err)
	pending, err := a.Pending()
	must(t, err)
	if len(pending) != 1 {
		t.Fatalf("pending %+v", pending)
	}
	_, err = a.Approve(pending[0].ID)
	must(t, err)
	must(t, b.Pull())
	if got, _ := b.Store.List(); len(got) != 1 || got[0].Name != "web" {
		t.Fatalf("hosts on b %+v", got)
	}
}

// an edited sync state cannot send the requests in the clear or keep a
// password in the address (#231)
func TestCheckEndpoint(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://e.example":         true,
		"https://e.example:9000/":   true,
		"http://127.0.0.1:9000":     true,
		"http://localhost:9000":     false,
		"http://[::1]:9000":         true,
		"http://e.example":          false,
		"http://10.0.0.1:9000":      false,
		"ftp://e.example":           false,
		"https://user:pw@e.example": false,
		"https://":                  false,
		"e.example":                 false,
	} {
		if err := CheckEndpoint(raw); (err == nil) != ok {
			t.Errorf("%q: %v", raw, err)
		}
	}
	if _, err := New(Config{Endpoint: "http://e.example", Bucket: "b", KeyID: "k"}, "s", nil); err == nil {
		t.Error("New opened a plain http endpoint")
	}
	// no error repeats a password of the address (#239)
	for _, raw := range []string{"https://u:pw@host:badport", "https://u:pw@host", "ftp://u:pw@host", "http://u:pw@e.example"} {
		if err := CheckEndpoint(raw); err == nil || strings.Contains(err.Error(), "pw") {
			t.Errorf("%q: %v", raw, err)
		}
	}
}
