package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshr.dev/internal/davstore"
	"sshr.dev/internal/folderstore"
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
	// S3 flags without --backend are not dropped in silence (#238)
	if _, err := (&storeFlags{s3: s3store.Config{Bucket: "b"}, given: true, s3Given: true}).setup(&syncclient.Client{}, "https://sync.example"); err == nil || !strings.Contains(err.Error(), "need --backend s3") {
		t.Errorf("S3 flags without --backend: %v", err)
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
	if _, err := openStore(syncclient.BackendRef{Kind: "ftp"}, "x"); err == nil {
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
		{[]string{"sync", "pull", "--bucket", "b"}, "WebDAV and Supabase flags are for sshr sync init and join"},
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

// store-key changes only the key and only of an account in a bucket, it
// stops before it asks for a secret (#128)
func TestStoreKeyMistakes(t *testing.T) {
	home := t.TempDir()
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"sync", "store-key"}, "not set up"},
		{[]string{"sync", "store-key", "--key-id", "K", "--bucket", "other"}, "takes only --key-id"},
		{[]string{"sync", "store-key", "--key-id", "K"}, "not set up"},
	} {
		_, errOut, code := sshrIn(t, home, c.args...)
		if code == 0 || !strings.Contains(errOut, c.want) || strings.Contains(errOut, "secret key") {
			t.Errorf("%v: %d %q, want %q", c.args, code, errOut, c.want)
		}
	}
	dir := filepath.Join(home, ".sshr", "sync")
	noErr(t, os.MkdirAll(dir, 0o700))
	noErr(t, os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"server":"https://sync.example"}`), 0o600))
	if _, errOut, code := sshrIn(t, home, "sync", "store-key", "--key-id", "K"); code == 0 || !strings.Contains(errOut, "through sshr-sync") {
		t.Errorf("store-key on an sshr-sync account: %d %q", code, errOut)
	}
}

func noErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// the WebDAV flags land in their config, a mix with the S3 ones or a
// missing one stops before a password is asked for, a later run opens the
// folder from the state and invite prints the flags without the password
// (#128)
func TestWebDAVFlags(t *testing.T) {
	args := []string{"--backend", "webdav", "--url", "https://cloud.example/dav/sshr", "--user", "u"}
	var f storeFlags
	for i := 0; i < len(args); i++ {
		ok, err := f.take(args, &i)
		if err != nil || !ok {
			t.Fatalf("%s: %v %v", args[i], ok, err)
		}
	}
	if f.backend != "webdav" || f.dav != (davstore.Config{URL: "https://cloud.example/dav/sshr", User: "u"}) || f.s3Given {
		t.Fatalf("got %+v", f)
	}
	t.Setenv("SSHR_WEBDAV_PASSWORD", "pw")
	for _, tc := range []struct {
		f      storeFlags
		server string
		err    string
	}{
		{storeFlags{backend: "webdav", dav: f.dav, davGiven: true, s3: s3store.Config{Bucket: "b"}, s3Given: true}, "", "are for --backend s3"},
		{storeFlags{backend: "s3", dav: f.dav, davGiven: true}, "", "are for --backend webdav"},
		{storeFlags{dav: f.dav, given: true, davGiven: true}, "", "need --backend webdav"},
		{storeFlags{backend: "webdav", dav: davstore.Config{URL: f.dav.URL}, davGiven: true}, "", "--user"},
		{storeFlags{backend: "webdav", dav: f.dav, davGiven: true}, "https://sync.example", "--server is for sshr-sync"},
		{storeFlags{backend: "webdav", dav: davstore.Config{URL: "http://cloud.example/dav", User: "u"}, davGiven: true}, "", "https://"},
	} {
		c := &syncclient.Client{}
		if _, err := tc.f.setup(c, tc.server); err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%+v: %v, want %q", tc.f, err, tc.err)
		}
		if c.Backend != nil || c.StoreSecret != "" {
			t.Errorf("%+v: a refused setup changed the client", tc.f)
		}
	}
	cfg, _ := json.Marshal(f.dav)
	ref := &syncclient.BackendRef{Kind: "webdav", Config: cfg}
	got, err := joinFlags("webdav "+f.dav.URL, ref)
	if err != nil || got != "--backend webdav --url https://cloud.example/dav/sshr --user u" {
		t.Errorf("join flags %q %v", got, err)
	}
	if _, err := openStore(*ref, "pw"); err != nil {
		t.Error(err)
	}
	if _, err := openStore(*ref, ""); err == nil {
		t.Error("opened a folder without a password")
	}
}

// the join line keeps a value with a space or shell characters as one
// argument (#258)
func TestJoinFlagsQuote(t *testing.T) {
	cfg, _ := json.Marshal(davstore.Config{URL: "https://cloud.example/dav/a;b $x", User: "John O'Doe"})
	got, err := joinFlags("", &syncclient.BackendRef{Kind: "webdav", Config: cfg})
	want := `--backend webdav --url 'https://cloud.example/dav/a;b $x' --user 'John O'\''Doe'`
	if err != nil || got != want {
		t.Errorf("join flags\n got %s\nwant %s", got, want)
	}
	if shellQuote("") != "''" || shellQuote("u") != "u" {
		t.Errorf("quote of plain values %q %q", shellQuote(""), shellQuote("u"))
	}
}

// the Supabase flags land in their place, a mix with other backends or a
// secret key stops before the sshr key is asked for, invite prints the
// public flags only, supabase-sql prints the SQL and a key (#128)
func TestSupabaseFlags(t *testing.T) {
	args := []string{"--backend", "supabase", "--url", "https://abc.supabase.co", "--key", "sb_publishable_x"}
	var f storeFlags
	for i := 0; i < len(args); i++ {
		ok, err := f.take(args, &i)
		if err != nil || !ok {
			t.Fatalf("%s: %v %v", args[i], ok, err)
		}
	}
	if f.backend != "supabase" || f.dav.URL != "https://abc.supabase.co" || f.sbKey != "sb_publishable_x" || !f.keyGiven {
		t.Fatalf("got %+v", f)
	}
	t.Setenv("SSHR_SUPABASE_KEY", strings.Repeat("ab", 32))
	for _, tc := range []struct {
		f   storeFlags
		err string
	}{
		{storeFlags{backend: "supabase", dav: davstore.Config{URL: f.dav.URL, User: "u"}, sbKey: f.sbKey, davGiven: true, keyGiven: true}, "not the S3 flags or --user"},
		{storeFlags{backend: "supabase", dav: davstore.Config{URL: f.dav.URL}, davGiven: true}, "--key <publishable key>"},
		{storeFlags{backend: "supabase", dav: davstore.Config{URL: f.dav.URL}, sbKey: "sb_secret_x", davGiven: true, keyGiven: true}, "secret key"},
		{storeFlags{backend: "supabase", dav: davstore.Config{URL: "http://abc.supabase.co"}, sbKey: f.sbKey, davGiven: true, keyGiven: true}, "https://"},
		{storeFlags{backend: "webdav", dav: davstore.Config{URL: f.dav.URL, User: "u"}, sbKey: f.sbKey, davGiven: true, keyGiven: true}, "are for --backend s3 or supabase"},
		{storeFlags{sbKey: f.sbKey, given: true, keyGiven: true}, "--key needs --backend supabase"},
	} {
		c := &syncclient.Client{}
		if _, err := tc.f.setup(c, ""); err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%+v: %v, want %q", tc.f, err, tc.err)
		}
		if c.Backend != nil || c.StoreSecret != "" {
			t.Errorf("%+v: a refused setup changed the client", tc.f)
		}
	}
	cfg, _ := json.Marshal(map[string]string{"url": "https://abc.supabase.co", "key": "sb_publishable_x"})
	ref := &syncclient.BackendRef{Kind: "supabase", Config: cfg}
	got, err := joinFlags("supabase https://abc.supabase.co", ref)
	if err != nil || got != "--backend supabase --url https://abc.supabase.co --key sb_publishable_x" {
		t.Errorf("join flags %q %v", got, err)
	}
	if _, err := openStore(*ref, strings.Repeat("ab", 32)); err != nil {
		t.Error(err)
	}
	if _, err := openStore(*ref, "short"); err == nil {
		t.Error("opened a project with a short sshr key")
	}
}

func TestSupabaseSQLCommand(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SSHR_SUPABASE_KEY", "")
	out, errOut, code := sshrIn(t, home, "sync", "supabase-sql")
	if code != 0 || !strings.Contains(out, "create schema if not exists sshr") || !strings.Contains(errOut, "sshr key of the account") || strings.Contains(out, "delete from sshr.keys") {
		t.Fatalf("supabase-sql: %d %q %q", code, out, errOut)
	}
	key := strings.Repeat("cd", 32)
	t.Setenv("SSHR_SUPABASE_KEY", key)
	out, errOut, _ = sshrIn(t, home, "sync", "supabase-sql")
	if strings.Contains(errOut, "sshr key of the account") || strings.Contains(out, key) {
		t.Errorf("supabase-sql with a key given: %q %q", out, errOut)
	}
	// a passphrase in the variable is refused, a trailing newline is not (#276)
	t.Setenv("SSHR_SUPABASE_KEY", "my secret phrase")
	if _, errOut, code := sshrIn(t, home, "sync", "supabase-sql"); code == 0 || !strings.Contains(errOut, "64 hex characters") {
		t.Errorf("supabase-sql with a passphrase: %d %q", code, errOut)
	}
	t.Setenv("SSHR_SUPABASE_KEY", key+"\n")
	if _, errOut, code := sshrIn(t, home, "sync", "supabase-sql"); code != 0 {
		t.Errorf("supabase-sql with a trailing newline: %d %q", code, errOut)
	}
	t.Setenv("SSHR_SUPABASE_KEY", key)
	out, errOut, _ = sshrIn(t, home, "sync", "supabase-sql", "--replace")
	if !strings.Contains(out, "delete from sshr.keys") || !strings.Contains(errOut, "sshr key of the account") {
		t.Errorf("supabase-sql --replace: %q %q", out, errOut)
	}
	// the old key in the variable is named after a change (#277)
	if !strings.Contains(errOut, "SSHR_SUPABASE_KEY still holds the old key") {
		t.Errorf("supabase-sql --replace with the variable set: %q", errOut)
	}
}

// TestSyncPrimaryTakesYes checks that sshr sync primary reads its own
// --yes instead of stopping with the usage of sshr sync (#300)
func TestSyncPrimaryTakesYes(t *testing.T) {
	home := t.TempDir()
	_, errOut, code := sshrIn(t, home, "sync", "primary", "abcd", "--yes")
	if code == 0 || strings.Contains(errOut, "Usage") || strings.Contains(errOut, "sshr sync [") {
		t.Fatalf("--yes did not reach sync primary: %d %q", code, errOut)
	}
}

// TestRecoveryWaitDays checks that --wait refuses a day count that would
// wrap around when turned into a duration (#311)
func TestRecoveryWaitDays(t *testing.T) {
	home := t.TempDir()
	_, errOut, code := sshrIn(t, home, "sync", "recovery", "create", "--wait", "106751991167301")
	if code == 0 || !strings.Contains(errOut, "from 1 to 366") {
		t.Fatalf("a huge --wait: %d %q", code, errOut)
	}
}

// a folder account takes --path only, init wants the folder empty, the
// join line names the folder, the folder has no key to replace (#128)
func TestFolderStoreFlags(t *testing.T) {
	dir := t.TempDir()
	c := &syncclient.Client{}
	f := storeFlags{backend: "folder", folder: folderstore.Config{Path: dir}, forInit: true}
	addr, err := f.setup(c, "")
	if err != nil || addr != "folder "+dir || c.BackendRef == nil || c.BackendRef.Kind != "folder" || c.StoreSecret != "" {
		t.Fatalf("setup %q %v %+v", addr, err, c.BackendRef)
	}
	got, err := joinFlags(addr, c.BackendRef)
	if err != nil || got != "--backend folder --path "+shellQuote(dir) {
		t.Errorf("join flags %q %v", got, err)
	}
	if _, err := openStore(*c.BackendRef, ""); err != nil {
		t.Error(err)
	}
	os.WriteFile(filepath.Join(dir, "account"), []byte("{}"), 0o600)
	if _, err := f.setup(&syncclient.Client{}, ""); err == nil || !strings.Contains(err.Error(), "holds an account") {
		t.Errorf("init in a folder that has an account: %v", err)
	}
	f.forInit = false
	if _, err := f.setup(&syncclient.Client{}, ""); err != nil {
		t.Errorf("join in a folder that has an account: %v", err)
	}
	for _, bad := range []storeFlags{
		{backend: "folder"},
		{backend: "folder", folder: folderstore.Config{Path: dir}, keyGiven: true},
	} {
		if _, err := bad.setup(&syncclient.Client{}, ""); err == nil {
			t.Errorf("%+v was taken", bad)
		}
	}
	if _, err := (&storeFlags{backend: "folder", folder: folderstore.Config{Path: dir}}).setup(&syncclient.Client{}, "https://x"); err == nil {
		t.Error("--server with a folder was taken")
	}
}
