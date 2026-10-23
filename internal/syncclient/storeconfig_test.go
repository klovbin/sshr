package syncclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshr.dev/internal/hosts"
	"sshr.dev/internal/vault"
)

// an account in an object store opens it again on the next run from the
// state and the secret in the keychain, Leave takes the secret away (#128)
func TestBackendKeptInState(t *testing.T) {
	useMemKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	store := newMemStore()
	ref := BackendRef{Kind: "mem", Config: json.RawMessage(`{"bucket":"b"}`)}
	dir, hostDir := t.TempDir(), t.TempDir()
	a := &Client{Store: &hosts.Store{Dir: hostDir}, Dir: dir, KeyPrefix: "a-", Log: &strings.Builder{},
		Backend: ObjectBackend{Store: store}, BackendRef: &ref, StoreSecret: "s3cret"}
	_, err := a.Store.Add(hosts.Host{Name: "web", Host: "10.0.0.1", User: "u"})
	must(t, err)
	must(t, a.Init("memory", "laptop"))

	var gotRef BackendRef
	var gotSecret string
	again := &Client{Store: &hosts.Store{Dir: hostDir}, Dir: dir, KeyPrefix: "a-", Log: &strings.Builder{},
		OpenBackend: func(r BackendRef, secret string) (Backend, error) {
			gotRef, gotSecret = r, secret
			return ObjectBackend{Store: store}, nil
		}}
	must(t, again.Push())
	var cfg struct{ Bucket string }
	json.Unmarshal(gotRef.Config, &cfg)
	if gotRef.Kind != "mem" || cfg.Bucket != "b" || gotSecret != "s3cret" {
		t.Fatalf("opened %+v with %q", gotRef, gotSecret)
	}

	blind := &Client{Store: &hosts.Store{Dir: hostDir}, Dir: dir, KeyPrefix: "a-", Log: &strings.Builder{}}
	if err := blind.Push(); err == nil || !strings.Contains(err.Error(), "cannot open") {
		t.Errorf("a client without an opener pushed: %v", err)
	}

	must(t, again.Leave(true))
	if _, ok, _ := vault.SecretGet("a-sync-store-secret"); ok {
		t.Error("the store secret stayed in the keychain after leave")
	}
}

// overStore writes over an object on every create, a store without the
// conditional write
type overStore struct{ *memStore }

func (s overStore) Create(name string, data []byte) error { return s.Put(name, data) }

// keepStore refuses every delete
type keepStore struct{ *memStore }

func (s keepStore) Delete(string) error { return errors.New("AccessDenied") }

// the probe takes a store that refuses the second create and turns down
// one that writes over it (#128)
func TestProbeCreate(t *testing.T) {
	good := newMemStore()
	must(t, ProbeCreate(good))
	if len(good.m) != 0 {
		t.Errorf("the probe left %v", good.m)
	}
	if err := ProbeCreate(overStore{newMemStore()}); err == nil || !strings.Contains(err.Error(), "wrote over") {
		t.Errorf("a store that writes over passed: %v", err)
	}
	// a probe object left behind is named (#237)
	if err := ProbeCreate(keepStore{newMemStore()}); err == nil || !strings.Contains(err.Error(), "did not delete the probe object probe/") {
		t.Errorf("a store that keeps the probe passed: %v", err)
	}
}

// the secret reaches the keychain only for an account that was saved, a
// failed init or join leaves none, the state never holds it (#232)
func TestStoreSecretOnlyForSavedAccount(t *testing.T) {
	useMemKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	ref := BackendRef{Kind: "mem", Config: json.RawMessage(`{}`)}
	mk := func(prefix string, store *memStore) *Client {
		return &Client{Store: &hosts.Store{Dir: t.TempDir()}, Dir: t.TempDir(), KeyPrefix: prefix, Log: &strings.Builder{},
			Backend: ObjectBackend{Store: store}, BackendRef: &ref, StoreSecret: "s3cret-" + prefix}
	}
	has := func(prefix string) bool {
		_, ok, _ := vault.SecretGet(prefix + "store-secret")
		return ok
	}

	// a store with an account already in it refuses a second one
	taken := newMemStore()
	must(t, mk("a-", taken).Init("memory", "first"))
	if err := mk("b-", taken).Init("memory", "second"); err == nil {
		t.Fatal("a second account went into a store that has one")
	}
	if has("b-") {
		t.Error("a failed init left the store secret")
	}
	// a join to an account the store does not hold
	j := mk("c-", taken)
	if _, err := j.Join("memory", strings.Repeat("0", 32)+"."+strings.Repeat("0", 20), "x"); err == nil {
		t.Fatal("joined an account the store does not hold")
	}
	if has("c-") {
		t.Error("a failed join left the store secret")
	}

	// a join that works keeps the secret, the state does not
	store, first, _ := objWorld(t)
	code, err := first.Invite()
	must(t, err)
	d := mk("d-", store)
	_, err = d.Join("memory", code, "third")
	must(t, err)
	if !has("d-") {
		t.Error("a join that worked has no store secret")
	}
	b, err := os.ReadFile(filepath.Join(d.Dir, "state.json"))
	must(t, err)
	if bytes.Contains(b, []byte("s3cret")) || !bytes.Contains(b, []byte(`"mem"`)) {
		t.Errorf("state %s", b)
	}
}

// a device whose store secret is gone can still leave, a key change it
// could not deliver asks for --force instead of a leave that never works
// (#236)
func TestLeaveWithoutStoreSecret(t *testing.T) {
	useMemKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	ref := BackendRef{Kind: "mem", Config: json.RawMessage(`{}`)}
	a := &Client{Store: &hosts.Store{Dir: t.TempDir()}, Dir: t.TempDir(), KeyPrefix: "a-", Log: &strings.Builder{},
		Backend: ObjectBackend{Store: newMemStore()}, BackendRef: &ref, StoreSecret: "s3cret"}
	must(t, a.Init("memory", "laptop"))
	vault.SecretDelete("a-store-secret")
	path := filepath.Join(a.Dir, "state.json")
	b, err := os.ReadFile(path)
	must(t, err)
	var st map[string]any
	must(t, json.Unmarshal(b, &st))
	st["rotation"] = map[string]any{}
	b, _ = json.Marshal(st)
	must(t, os.WriteFile(path, b, 0o600))

	again := &Client{Store: a.Store, Dir: a.Dir, KeyPrefix: "a-", Log: &strings.Builder{},
		OpenBackend: func(BackendRef, string) (Backend, error) { return nil, errors.New("not reached") }}
	if err := again.Leave(false); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("leave with an undelivered key: %v", err)
	}
	// a keychain that fails for now is not a reason for --force (#241)
	failing := &Client{Store: a.Store, Dir: a.Dir, KeyPrefix: "a-", Log: &strings.Builder{}, OpenBackend: again.OpenBackend}
	vault.SetKeychain(brokenKeychain{})
	err = failing.Leave(false)
	useMemKeychain(t)
	if err == nil || strings.Contains(err.Error(), "--force") {
		t.Errorf("leave with a failing keychain: %v", err)
	}
	must(t, again.Leave(true))
	if _, err := os.Stat(path); err == nil {
		t.Error("leave --force kept the sync state")
	}
}

// brokenKeychain fails every call, a locked or unreachable keychain
type brokenKeychain struct{}

func (brokenKeychain) Get(string) (string, error) { return "", errors.New("keychain locked") }
func (brokenKeychain) Set(string, string) error   { return errors.New("keychain locked") }
func (brokenKeychain) Delete(string) error        { return errors.New("keychain locked") }

// a new store key replaces the old one in the state and the keychain, also
// when the old secret is gone, a key that does not read the account
// changes nothing (#128)
func TestReplaceStoreKey(t *testing.T) {
	useMemKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	store := newMemStore()
	ref := BackendRef{Kind: "mem", Config: json.RawMessage(`{"key":"old"}`)}
	a := &Client{Store: &hosts.Store{Dir: t.TempDir()}, Dir: t.TempDir(), KeyPrefix: "a-", Log: &strings.Builder{},
		Backend: ObjectBackend{Store: store}, BackendRef: &ref, StoreSecret: "old-secret"}
	must(t, a.Init("memory", "laptop"))
	vault.SecretDelete("a-store-secret")
	mk := func() *Client {
		return &Client{Store: a.Store, Dir: a.Dir, KeyPrefix: "a-", Log: &strings.Builder{}}
	}

	got, err := mk().StoreRef()
	must(t, err)
	if got == nil || got.Kind != "mem" {
		t.Fatalf("store ref %+v", got)
	}
	newRef := BackendRef{Kind: "mem", Config: json.RawMessage(`{"key":"new"}`)}
	if err := mk().ReplaceStoreKey(newRef, "x", ObjectBackend{Store: newMemStore()}); err == nil {
		t.Error("a key that does not read the account was taken")
	}
	if _, ok, _ := vault.SecretGet("a-store-secret"); ok {
		t.Error("a refused key reached the keychain")
	}
	if err := mk().ReplaceStoreKey(BackendRef{Kind: "s3"}, "x", ObjectBackend{Store: store}); err == nil {
		t.Error("a key of another kind of store was taken")
	}
	must(t, mk().ReplaceStoreKey(newRef, "new-secret", ObjectBackend{Store: store}))

	var opened BackendRef
	var secret string
	c := mk()
	c.OpenBackend = func(r BackendRef, s string) (Backend, error) {
		opened, secret = r, s
		return ObjectBackend{Store: store}, nil
	}
	must(t, c.Push())
	var cfg struct{ Key string }
	json.Unmarshal(opened.Config, &cfg)
	if cfg.Key != "new" || secret != "new-secret" {
		t.Errorf("opened %s with %q", opened.Config, secret)
	}
}
