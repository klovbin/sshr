package supastore

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

const pubKey = "sb_publishable_test"

var testKey = strings.Repeat("ab", 32)

// fakeREST answers the sshr_* functions of setup.sql the way PostgREST
// does, PTxyz errors become status xyz with the code in the body
type fakeREST struct {
	mu      sync.Mutex
	objects map[string][]byte
	gets    int
}

func (f *fakeREST) fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"code":%q,"message":"x"}`, code)
}

func (f *fakeREST) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method != "POST" {
		f.gets++
		f.fail(w, 405, "PGRST117")
		return
	}
	if r.Header.Get("apikey") != pubKey {
		f.fail(w, 401, "")
		return
	}
	fn := strings.TrimPrefix(r.URL.Path, "/rest/v1/rpc/")
	var a struct {
		Name   string `json:"p_name"`
		Max    int    `json:"p_max"`
		Data   string `json:"p_data"`
		Prefix string `json:"p_prefix"`
		After  string `json:"p_after"`
	}
	json.NewDecoder(r.Body).Decode(&a)
	if r.Header.Get("x-sshr-key") != testKey {
		f.fail(w, 403, "PT403")
		return
	}
	switch fn {
	case "sshr_get":
		d, ok := f.objects[a.Name]
		if !ok {
			f.fail(w, 404, "PT404")
			return
		}
		if len(d) > a.Max {
			f.fail(w, 413, "PT413")
			return
		}
		// Postgres breaks base64 lines at 76
		enc := base64.StdEncoding.EncodeToString(d)
		var lines []string
		for len(enc) > 76 {
			lines, enc = append(lines, enc[:76]), enc[76:]
		}
		json.NewEncoder(w).Encode(strings.Join(append(lines, enc), "\n"))
	case "sshr_put":
		d, _ := base64.StdEncoding.DecodeString(a.Data)
		f.objects[a.Name] = d
		w.WriteHeader(204)
	case "sshr_create":
		d, _ := base64.StdEncoding.DecodeString(a.Data)
		if old, ok := f.objects[a.Name]; ok {
			if string(old) == string(d) {
				w.WriteHeader(204)
				return
			}
			f.fail(w, 409, "PT409")
			return
		}
		f.objects[a.Name] = d
		w.WriteHeader(204)
	case "sshr_delete":
		delete(f.objects, a.Name)
		w.WriteHeader(204)
	case "sshr_list":
		var names []string
		for n := range f.objects {
			if strings.HasPrefix(n, a.Prefix) && n > a.After {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		if len(names) > listPage {
			names = names[:listPage]
		}
		out := []map[string]string{}
		for _, n := range names {
			out = append(out, map[string]string{"name": n})
		}
		json.NewEncoder(w).Encode(out)
	default:
		f.fail(w, 404, "PGRST202")
	}
}

func newFake(t *testing.T) (*Store, *fakeREST) {
	t.Helper()
	f := &fakeREST{objects: map[string][]byte{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	s, err := New(Config{URL: srv.URL, Key: pubKey}, testKey, nil)
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

// the store does what ObjectBackend needs through POST calls only (#128)
func TestStoreObjects(t *testing.T) {
	s, f := newFake(t)
	if _, err := s.Get("account", 10); !errors.Is(err, syncclient.ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
	big := make([]byte, 5000)
	for i := range big {
		big[i] = byte(i)
	}
	must(t, s.Create("blobs/x", big))
	must(t, s.Create("blobs/x", big))
	if err := s.Create("blobs/x", []byte("other")); !errors.Is(err, syncclient.ErrExists) {
		t.Errorf("second create: %v", err)
	}
	b, err := s.Get("blobs/x", len(big))
	if err != nil || string(b) != string(big) {
		t.Errorf("get %d bytes %v", len(b), err)
	}
	if _, err := s.Get("blobs/x", 0); !errors.Is(err, syncclient.ErrTooLarge) {
		t.Errorf("too large: %v", err)
	}
	must(t, s.Put("blobs/x", []byte("new")))
	for i := 0; i < 2500; i++ {
		must(t, s.Put(fmt.Sprintf("manifests/%020d", i), []byte("m")))
	}
	names, err := s.List("manifests/")
	if err != nil || len(names) != 2500 || names[0] != fmt.Sprintf("manifests/%020d", 0) {
		t.Errorf("list %d names %v", len(names), err)
	}
	must(t, s.Delete("blobs/x"))
	must(t, s.Delete("blobs/x"))
	must(t, syncclient.ProbeCreate(s))
	if f.gets != 0 {
		t.Errorf("%d GET requests, every call must be a POST", f.gets)
	}
}

// a wrong sshr key is an error on every call, never an empty store
func TestKeyRefused(t *testing.T) {
	_, f := newFake(t)
	srv := httptest.NewServer(f)
	defer srv.Close()
	s, err := New(Config{URL: srv.URL, Key: pubKey}, strings.Repeat("cd", 32), nil)
	must(t, err)
	_, err = s.Get("account", 10)
	calls := []error{err, s.Delete("account"), s.Put("account", []byte("a"))}
	_, err = s.List("devices/")
	calls = append(calls, err)
	for i, err := range calls {
		if !errors.Is(err, ErrKeyRefused) {
			t.Errorf("call %d: %v", i, err)
		}
	}
}

// the answers of a project that cannot serve are said in words
func TestAnswerErrors(t *testing.T) {
	for _, c := range []struct {
		status int
		code   string
		want   string
	}{
		{540, "", "paused"},
		{402, "exceed_db_size_quota", "quota"},
		{405, "25006", "read-only"},
		{404, "PGRST202", "run the SQL"},
		{401, "", "publishable key"},
		{302, "", "redirects"},
		{503, "", "answered 503"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if c.status == 302 {
				http.Redirect(w, r, "https://elsewhere.example/", 302)
				return
			}
			w.WriteHeader(c.status)
			fmt.Fprintf(w, `{"code":%q}`, c.code)
		}))
		s, err := New(Config{URL: srv.URL, Key: pubKey}, testKey, nil)
		must(t, err)
		err = s.Delete("account")
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), testKey) {
			t.Errorf("%d %s: %v", c.status, c.code, err)
		}
	}
}

func TestCheckKeyAndAddress(t *testing.T) {
	jwt := func(role string) string {
		p := base64.RawURLEncoding.EncodeToString([]byte(`{"role":"` + role + `"}`))
		return "eyJhbGciOiJIUzI1NiJ9." + p + ".sig"
	}
	for k, ok := range map[string]bool{
		"sb_publishable_abc": true,
		jwt("anon"):          true,
		"sb_secret_abc":      false,
		jwt("service_role"):  false,
		jwt("authenticated"): false,
		"just-some-key":      false,
	} {
		if err := CheckKey(k); (err == nil) != ok {
			t.Errorf("%q: %v", k, err)
		}
	}
	for _, c := range []Config{
		{URL: "http://abc.supabase.co", Key: pubKey},
		{URL: "https://abc.supabase.co/rest/v1", Key: pubKey},
		{URL: "https://abc.supabase.co", Key: "sb_secret_x"},
	} {
		if _, err := New(c, testKey, nil); err == nil {
			t.Errorf("%+v was taken", c)
		}
	}
	if _, err := New(Config{URL: "https://abc.supabase.co", Key: pubKey}, "short", nil); err == nil {
		t.Error("a short sshr key was taken")
	}
}

// the setup SQL holds the hash of the key and never the key
func TestSetupSQL(t *testing.T) {
	sql := SetupSQL(testKey, false)
	sum := sha256.Sum256([]byte(testKey))
	if strings.Contains(sql, testKey) || !strings.Contains(sql, `'\x`+hex.EncodeToString(sum[:])+`'`) || strings.Contains(sql, "{{") {
		t.Errorf("setup SQL does not carry the hash alone")
	}
	if r := SetupSQL(testKey, true); !strings.Contains(r, "delete from sshr.keys;\ninsert into sshr.keys") || strings.Contains(sql, "delete from sshr.keys") {
		t.Error("only the replace SQL drops the old keys")
	}
	k, err := NewKey()
	if err != nil || !keyRe.MatchString(k) {
		t.Errorf("new key %q %v", k, err)
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

// two devices pair and sync through a Supabase project (#128)
func TestSyncThroughSupabase(t *testing.T) {
	vault.SetKeychain(&memKeychain{m: map[string]string{}})
	vault.ResetForTest(filepath.Join(t.TempDir(), ".lock"))
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	s, _ := newFake(t)
	mk := func(p string) *syncclient.Client {
		return &syncclient.Client{Store: &hosts.Store{Dir: t.TempDir()}, Dir: t.TempDir(), KeyPrefix: p,
			Backend: syncclient.ObjectBackend{Store: s}, Log: io.Discard}
	}
	a, b := mk("a-"), mk("b-")
	_, err := a.Store.Add(hosts.Host{Name: "web", Host: "10.0.0.1", User: "u"})
	must(t, err)
	must(t, a.Init("supabase", "laptop"))
	code, err := a.Invite()
	must(t, err)
	_, err = b.Join("supabase", code, "desktop")
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

// an answer longer than asked for is not read to the end (#270)
func TestAnswerSizeLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`"`))
		chunk := []byte(strings.Repeat("A", 1<<16))
		for i := 0; i < 200; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
		w.Write([]byte(`"`))
	}))
	defer srv.Close()
	s, err := New(Config{URL: srv.URL, Key: pubKey}, testKey, nil)
	must(t, err)
	if _, err := s.Get("blobs/x", 10); !errors.Is(err, syncclient.ErrTooLarge) {
		t.Errorf("a long answer to a small get: %v", err)
	}
	if err := s.Delete("blobs/x"); !errors.Is(err, syncclient.ErrTooLarge) {
		t.Errorf("a long answer to a delete: %v", err)
	}
}
