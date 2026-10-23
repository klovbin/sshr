package syncclient

import (
	"encoding/json"
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
}
