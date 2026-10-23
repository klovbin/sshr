package main

import (
	"encoding/json"
	"os"
	"path/filepath"
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
		ok, err := f.take(args, &i)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			rest = append(rest, args[i])
		}
	}
	want := s3store.Config{Endpoint: "https://e.example", Bucket: "b", Prefix: "p", Region: "eu", KeyID: "K"}
	if f.backend != "s3" || f.s3 != want || !f.given || strings.Join(rest, " ") != "--name x" {
		t.Fatalf("got %+v rest %v", f, rest)
	}
	// the next flag or the end is not a value (#235)
	for _, bad := range [][]string{{"--bucket", "--key-id", "K"}, {"--bucket"}} {
		var g storeFlags
		i := 0
		if ok, err := g.take(bad, &i); !ok || err == nil || g.s3.Bucket != "" {
			t.Errorf("%v: took %+v, %v", bad, g, err)
		}
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
	got, err := joinFlags("s3 https://e.example b/p", ref)
	if err != nil || got != "--backend s3 --endpoint https://e.example --bucket b --prefix p --key-id K" {
		t.Errorf("join flags %q %v", got, err)
	}
	if got, err := joinFlags("https://sync.example", nil); err != nil || got != "--server https://sync.example" {
		t.Errorf("join flags %q %v", got, err)
	}
	// a broken config is an error, not a join line with empty values (#234)
	if got, err := joinFlags("", &syncclient.BackendRef{Kind: "s3", Config: json.RawMessage(`[`)}); err == nil {
		t.Errorf("join flags of a broken config %q", got)
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

// a store flag outside init and join, or one without a value, stops the
// command before it reads the sync state or asks for a secret (#235)
func TestSyncStoreFlagMistakes(t *testing.T) {
	home := t.TempDir()
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"sync", "pull", "--bucket", "b"}, "are for sshr sync init and join"},
		{[]string{"sync", "init", "--backend", "s3", "--endpoint", "https://e.example", "--bucket", "--key-id", "K"}, "--bucket needs a value"},
		{[]string{"sync", "join", "--server"}, "--server needs a value"},
	} {
		_, errOut, code := sshrIn(t, home, c.args...)
		if code == 0 || !strings.Contains(errOut, c.want) {
			t.Errorf("%v: %d %q, want %q", c.args, code, errOut, c.want)
		}
	}
}

// a wrong join or a machine that already syncs stops before the secret is
// asked for and before the bucket gets a probe (#233)
func TestSyncStoreChecksBeforeSecret(t *testing.T) {
	home := t.TempDir()
	s3 := []string{"--backend", "s3", "--endpoint", "https://127.0.0.1:1", "--bucket", "b", "--key-id", "K"}
	_, errOut, code := sshrIn(t, home, append([]string{"sync", "join"}, s3...)...)
	if code == 0 || !strings.Contains(errOut, "sshr sync join --server <url> <code>") || strings.Contains(errOut, "secret") {
		t.Errorf("join without a code: %d %q", code, errOut)
	}
	dir := filepath.Join(home, ".sshr", "sync")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"init", "join"} {
		args := append([]string{"sync", sub}, s3...)
		if sub == "join" {
			args = append(args, "code")
		}
		_, errOut, code := sshrIn(t, home, args...)
		if code == 0 || !strings.Contains(errOut, "already set up here") {
			t.Errorf("%s on a machine that syncs: %d %q", sub, code, errOut)
		}
	}
}
