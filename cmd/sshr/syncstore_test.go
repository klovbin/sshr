package main

import (
	"encoding/json"
	"strings"
	"testing"

	"sshr.dev/internal/s3store"
	"sshr.dev/internal/syncclient"
)

// the S3 flags of sshr sync init and join land in the config, a bad set
// stops before anything is asked or sent (#128)
func TestStoreFlags(t *testing.T) {
	args := []string{"--backend", "s3", "--endpoint", "https://e.example", "--bucket", "b",
		"--prefix", "p", "--region", "eu", "--key-id", "K", "--name", "x"}
	var f storeFlags
	var rest []string
	for i := 0; i < len(args); i++ {
		if !f.take(args, &i) {
			rest = append(rest, args[i])
		}
	}
	want := s3store.Config{Endpoint: "https://e.example", Bucket: "b", Prefix: "p", Region: "eu", KeyID: "K"}
	if f.backend != "s3" || f.s3 != want || strings.Join(rest, " ") != "--name x" {
		t.Fatalf("got %+v rest %v", f, rest)
	}

	t.Setenv("SSHR_S3_SECRET", "s")
	for _, tc := range []struct {
		f      storeFlags
		server string
		err    string
	}{
		{storeFlags{backend: "ftp"}, "", "unknown sync backend"},
		{storeFlags{backend: "s3", s3: want}, "https://sync.example", "--server is for sshr-sync"},
		{storeFlags{backend: "s3", s3: s3store.Config{Endpoint: "https://e.example", Bucket: "b"}}, "", "--key-id"},
		{storeFlags{backend: "s3", s3: s3store.Config{Endpoint: "http://e.example", Bucket: "b", KeyID: "K"}}, "", "https://"},
	} {
		c := &syncclient.Client{}
		if _, err := tc.f.setup(c, tc.server); err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%+v: %v, want %q", tc.f, err, tc.err)
		}
		if c.Backend != nil || c.BackendRef != nil || c.StoreSecret != "" {
			t.Errorf("%+v: a refused setup changed the client", tc.f)
		}
	}
	if s, err := (&storeFlags{}).setup(&syncclient.Client{}, "https://sync.example"); s != "https://sync.example" || err != nil {
		t.Errorf("without --backend: %q %v", s, err)
	}
}

// a new device gets the flags of the bucket and never the secret, a later
// run opens the bucket from the state (#128)
func TestJoinFlagsAndOpenStore(t *testing.T) {
	cfg, _ := json.Marshal(s3store.Config{Endpoint: "https://e.example", Bucket: "b", Prefix: "p", KeyID: "K"})
	ref := &syncclient.BackendRef{Kind: "s3", Config: cfg}
	got := joinFlags(&syncclient.Status{Server: "s3 https://e.example b/p", Backend: ref})
	if got != "--backend s3 --endpoint https://e.example --bucket b --prefix p --key-id K" {
		t.Errorf("join flags %q", got)
	}
	if got := joinFlags(&syncclient.Status{Server: "https://sync.example"}); got != "--server https://sync.example" {
		t.Errorf("join flags %q", got)
	}
	if _, err := openStore(*ref, "secret"); err != nil {
		t.Error(err)
	}
	if _, err := openStore(syncclient.BackendRef{Kind: "webdav"}, "x"); err == nil {
		t.Error("opened an unknown kind")
	}
	if _, err := openStore(*ref, ""); err == nil {
		t.Error("opened a bucket without a secret")
	}
}
