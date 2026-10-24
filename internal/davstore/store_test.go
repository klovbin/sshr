package davstore

import (
	"errors"
	"fmt"
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

// fakeDAV is a WebDAV server in memory with what sync uses: GET, PUT with
// If-None-Match: *, DELETE, MKCOL and PROPFIND Depth 1, a PUT into a
// missing folder answers 409 as RFC 4918 says
type fakeDAV struct {
	mu    sync.Mutex
	files map[string][]byte
	dirs  map[string]bool
	root  string
	// fullHref answers hrefs as full URLs with escaped names, as some
	// servers do
	fullHref bool
	methods  []string
}

func (f *fakeDAV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, p, ok := r.BasicAuth(); !ok || u != "u" || p != "pw" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.methods = append(f.methods, r.Method)
	p := r.URL.Path
	parent := p[:strings.LastIndex(strings.TrimSuffix(p, "/"), "/")+1]
	switch r.Method {
	case "GET":
		b, ok := f.files[p]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write(b)
	case "PUT":
		if !f.dirs[parent] {
			w.WriteHeader(http.StatusConflict)
			return
		}
		if _, ok := f.files[p]; ok && r.Header.Get("If-None-Match") == "*" {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		b, _ := io.ReadAll(r.Body)
		f.files[p] = b
		w.WriteHeader(http.StatusCreated)
	case "DELETE":
		if _, ok := f.files[p]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(f.files, p)
		w.WriteHeader(http.StatusNoContent)
	case "MKCOL":
		if f.dirs[p] {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !f.dirs[parent] {
			w.WriteHeader(http.StatusConflict)
			return
		}
		f.dirs[p] = true
		w.WriteHeader(http.StatusCreated)
	case "PROPFIND":
		if r.Header.Get("Depth") != "1" || !f.dirs[p] {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var names []string
		for n := range f.files {
			if strings.HasPrefix(n, p) && !strings.Contains(n[len(p):], "/") {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		w.WriteHeader(http.StatusMultiStatus)
		fmt.Fprintf(w, `<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>%s</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response>`, p)
		for n := range f.dirs {
			if strings.HasPrefix(n, p) && n != p && !strings.Contains(strings.TrimSuffix(n[len(p):], "/"), "/") {
				fmt.Fprintf(w, `<d:response><d:href>%s</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response>`, n)
			}
		}
		for _, n := range names {
			href := n
			if f.fullHref {
				href = "https://cloud.example" + strings.ReplaceAll(n, "/sshr", "/%73shr")
			}
			fmt.Fprintf(w, `<d:response><d:href>%s</d:href><d:propstat><d:prop><d:resourcetype/></d:prop></d:propstat></d:response>`, href)
		}
		fmt.Fprint(w, `</d:multistatus>`)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func newDAV(t *testing.T) (*Store, *fakeDAV) {
	t.Helper()
	f := &fakeDAV{files: map[string][]byte{}, dirs: map[string]bool{"/": true, "/dav/": true}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	s, err := New(Config{URL: srv.URL + "/dav/sshr", User: "u"}, "pw", nil)
	if err != nil {
		t.Fatal(err)
	}
	return s, f
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// the store does what ObjectBackend needs, folders appear on the first
// write, a second create of one name is refused (#128)
func TestStoreObjects(t *testing.T) {
	s, f := newDAV(t)
	if _, err := s.Get("account", 10); !errors.Is(err, syncclient.ErrNotFound) {
		t.Errorf("missing object: %v", err)
	}
	if names, err := s.List("devices/"); err != nil || len(names) != 0 {
		t.Errorf("missing folder: %v %v", names, err)
	}
	must(t, s.Create("manifests/00000000000000000001", []byte("one")))
	if err := s.Create("manifests/00000000000000000001", []byte("two")); !errors.Is(err, syncclient.ErrExists) {
		t.Errorf("second create: %v", err)
	}
	must(t, s.Put("manifests/00000000000000000002", []byte("2")))
	must(t, s.Put("manifests/00000000000000000002", []byte("22")))
	b, err := s.Get("manifests/00000000000000000002", 10)
	if err != nil || string(b) != "22" {
		t.Errorf("get %q %v", b, err)
	}
	if _, err := s.Get("manifests/00000000000000000002", 1); !errors.Is(err, syncclient.ErrTooLarge) {
		t.Errorf("too large: %v", err)
	}
	for _, full := range []bool{false, true} {
		f.fullHref = full
		names, err := s.List("manifests/")
		must(t, err)
		if strings.Join(names, ",") != "manifests/00000000000000000001,manifests/00000000000000000002" {
			t.Errorf("list (full hrefs %v) %v", full, names)
		}
	}
	must(t, s.Delete("manifests/00000000000000000001"))
	must(t, s.Delete("manifests/00000000000000000001"))
	must(t, syncclient.ProbeCreate(s))
}

// a wrong password is named as such and never shows in the error
func TestStoreRefusedLogin(t *testing.T) {
	_, f := newDAV(t)
	srv := httptest.NewServer(f)
	defer srv.Close()
	s, err := New(Config{URL: srv.URL + "/dav/sshr", User: "u"}, "wrong-secret", nil)
	must(t, err)
	_, err = s.Get("account", 10)
	if err == nil || !strings.Contains(err.Error(), "refused the user or password") || strings.Contains(err.Error(), "wrong-secret") {
		t.Errorf("refused login: %v", err)
	}
	if _, err := New(Config{URL: "http://cloud.example/dav", User: "u"}, "pw", nil); err == nil {
		t.Error("opened a plain http address")
	}
}

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

// two devices pair and sync through a WebDAV folder (#128)
func TestSyncThroughWebDAV(t *testing.T) {
	vault.SetKeychain(&memKeychain{m: map[string]string{}})
	vault.ResetForTest(filepath.Join(t.TempDir(), ".lock"))
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	s, _ := newDAV(t)
	mk := func(p string) *syncclient.Client {
		return &syncclient.Client{Store: &hosts.Store{Dir: t.TempDir()}, Dir: t.TempDir(), KeyPrefix: p,
			Backend: syncclient.ObjectBackend{Store: s}, Log: io.Discard}
	}
	a, b := mk("a-"), mk("b-")
	_, err := a.Store.Add(hosts.Host{Name: "web", Host: "10.0.0.1", User: "u"})
	must(t, err)
	must(t, a.Init("webdav", "laptop"))
	code, err := a.Invite()
	must(t, err)
	_, err = b.Join("webdav", code, "desktop")
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

// a redirect is an error, not a write that never happened, and the
// password does not follow it (#253)
func TestStoreRefusesRedirects(t *testing.T) {
	var gotAuth []string
	var mu sync.Mutex
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Write([]byte("<html>login</html>"))
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer redirect.Close()
	s, err := New(Config{URL: redirect.URL + "/dav/sshr", User: "u"}, "pw", nil)
	must(t, err)
	if err := s.Put("blobs/x", []byte("1")); err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Errorf("put through a redirect: %v", err)
	}
	if err := s.Create("manifests/1", []byte("1")); err == nil {
		t.Error("create through a redirect")
	}
	if err := s.Delete("blobs/x"); err == nil {
		t.Error("delete through a redirect")
	}
	if _, err := s.Get("blobs/x", 0); err == nil {
		t.Error("get through a redirect")
	}
	if len(gotAuth) != 0 {
		t.Errorf("the redirect target was asked %d times", len(gotAuth))
	}
}
