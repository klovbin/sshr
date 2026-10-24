package supastore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sshr.dev/internal/hosts"
	"sshr.dev/internal/syncclient"
	"sshr.dev/internal/vault"
)

// realREST starts PostgreSQL and PostgREST in a temporary folder with the
// roles Supabase has and runs setup.sql, the test is skipped when the
// programs are not on PATH (nix shell nixpkgs#postgresql_17 nixpkgs#postgrest),
// url is a proxy that takes /rest/v1 off as the gateway of Supabase does,
// rest is PostgREST itself
func realREST(t *testing.T) (url, rest, jwtSecret string, runSQL func(string)) {
	t.Helper()
	if testing.Short() {
		t.Skip("starts PostgreSQL")
	}
	for _, p := range []string{"initdb", "pg_ctl", "psql", "postgrest"} {
		if _, err := exec.LookPath(p); err != nil {
			t.Skipf("%s is not on PATH", p)
		}
	}
	dir := t.TempDir()
	data, sock := filepath.Join(dir, "data"), filepath.Join(dir, "s")
	os.MkdirAll(sock, 0o700)
	run := func(name string, args ...string) {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
	}
	run("initdb", "-D", data, "-U", "postgres", "--auth=trust", "--no-sync")
	pgPort, restPort := freePort(t), freePort(t)
	run("pg_ctl", "-D", data, "-l", filepath.Join(dir, "pg.log"), "-w",
		"-o", fmt.Sprintf("-p %d -k %s -c listen_addresses=127.0.0.1 -c fsync=off", pgPort, sock), "start")
	t.Cleanup(func() { exec.Command("pg_ctl", "-D", data, "-m", "immediate", "stop").Run() })
	psql := func(sql string) {
		t.Helper()
		run("psql", "-h", sock, "-p", fmt.Sprint(pgPort), "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-q", "-c", sql)
	}
	// the roles and default grants of a Supabase project
	psql(`create role anon nologin; create role authenticated nologin;
		create role authenticator login noinherit; grant anon, authenticated to authenticator;
		alter role anon set statement_timeout = '3s';
		grant usage on schema public to anon, authenticated;
		alter default privileges in schema public grant all on functions to anon, authenticated;
		alter default privileges in schema public grant all on tables to anon, authenticated;`)
	sqlFile := filepath.Join(dir, "setup.sql")
	os.WriteFile(sqlFile, []byte(SetupSQL(testKey, false)), 0o600)
	run("psql", "-h", sock, "-p", fmt.Sprint(pgPort), "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-q", "-f", sqlFile)

	jwtSecret = strings.Repeat("s", 40)
	cmd := exec.Command("postgrest")
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("PGRST_DB_URI=postgres://authenticator@127.0.0.1:%d/postgres", pgPort),
		"PGRST_DB_SCHEMAS=public", "PGRST_DB_ANON_ROLE=anon", "PGRST_JWT_SECRET="+jwtSecret,
		"PGRST_SERVER_HOST=127.0.0.1", fmt.Sprintf("PGRST_SERVER_PORT=%d", restPort), "PGRST_LOG_LEVEL=crit")
	log, _ := os.Create(filepath.Join(dir, "postgrest.log"))
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	rest = fmt.Sprintf("http://127.0.0.1:%d", restPort)
	// ready once the schema cache is loaded, before that it answers 503
	for i := 0; ; i++ {
		if resp, err := http.Get(rest + "/"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if i > 100 {
			b, _ := os.ReadFile(filepath.Join(dir, "postgrest.log"))
			t.Fatalf("PostgREST did not start:\n%s", b)
		}
		time.Sleep(100 * time.Millisecond)
	}
	target, _ := neturl.Parse(rest)
	proxy := httputil.NewSingleHostReverseProxy(target)
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/rest/v1/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/rest/v1")
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(gateway.Close)
	runSQL = func(sql string) {
		t.Helper()
		f := filepath.Join(dir, "run.sql")
		os.WriteFile(f, []byte(sql), 0o600)
		run("psql", "-h", sock, "-p", fmt.Sprint(pgPort), "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-q", "-f", f)
	}
	return gateway.URL, rest, jwtSecret, runSQL
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// hs256 signs a JWT with claims for PostgREST
func hs256(secret, claims string) string {
	enc := base64.RawURLEncoding
	head := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc.EncodeToString([]byte(claims))
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(head))
	return head + "." + enc.EncodeToString(m.Sum(nil))
}

// the SQL of setup.sql on a real PostgreSQL behind PostgREST does what the
// adapter needs and nothing more (#128)
func TestRealPostgres(t *testing.T) {
	url, rest, secret, _ := realREST(t)
	s, err := New(Config{URL: url, Key: pubKey}, testKey, nil)
	must(t, err)

	// objects, paging and names of the wrong shape
	for i := 0; i < 1001; i++ {
		must(t, s.Put(fmt.Sprintf("manifests/%020d", i), []byte{byte(i)}))
	}
	must(t, s.Put("devices/"+strings.Repeat("a", 32), []byte("d")))
	names, err := s.List("manifests/")
	if err != nil || len(names) != 1001 {
		t.Fatalf("list %d %v", len(names), err)
	}
	if names, _ := s.List("devices/"); len(names) != 1 {
		t.Errorf("devices %v", names)
	}
	if err := s.Put("devices/../x", []byte("x")); err == nil {
		t.Error("a name of the wrong shape was stored")
	}
	if _, err := s.Get("account", 10); !errors.Is(err, syncclient.ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
	if _, err := s.Get(fmt.Sprintf("manifests/%020d", 7), 0); !errors.Is(err, syncclient.ErrTooLarge) {
		t.Errorf("too large: %v", err)
	}
	big := make([]byte, 8<<20)
	for i := range big {
		big[i] = byte(i * 7)
	}
	must(t, s.Create("manifests/"+strings.Repeat("9", 20), big))
	got, err := s.Get("manifests/"+strings.Repeat("9", 20), len(big))
	if err != nil || len(got) != len(big) || string(got[:1000]) != string(big[:1000]) || got[len(got)-1] != big[len(big)-1] {
		t.Errorf("8 MiB round trip: %d bytes %v", len(got), err)
	}
	must(t, syncclient.ProbeCreate(s))

	// one winner of twenty creates at once, the same bytes again succeed
	name := "manifests/" + strings.Repeat("5", 20)
	var wg sync.WaitGroup
	results := make([]error, 20)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = s.Create(name, []byte(fmt.Sprintf("device %d", i)))
		}(i)
	}
	wg.Wait()
	winner := -1
	for i, err := range results {
		switch {
		case err == nil && winner < 0:
			winner = i
		case err == nil:
			t.Errorf("creates %d and %d both won", winner, i)
		case !errors.Is(err, syncclient.ErrExists):
			t.Errorf("create %d: %v", i, err)
		}
	}
	if winner < 0 {
		t.Fatal("no create won")
	}
	if b, _ := s.Get(name, 100); string(b) != fmt.Sprintf("device %d", winner) {
		t.Errorf("stored %q, winner %d", b, winner)
	}
	must(t, s.Create(name, []byte(fmt.Sprintf("device %d", winner))))

	// a wrong key is refused on every call
	wrong, err := New(Config{URL: url, Key: pubKey}, strings.Repeat("cd", 32), nil)
	must(t, err)
	_, e1 := wrong.Get("account", 10)
	_, e2 := wrong.List("manifests/")
	for i, err := range []error{e1, e2, wrong.Delete(name), wrong.Put("account", []byte("a")), wrong.Create("account", []byte("a"))} {
		if !errors.Is(err, ErrKeyRefused) {
			t.Errorf("wrong key, call %d: %v", i, err)
		}
	}
	if b, _ := s.Get(name, 100); len(b) == 0 {
		t.Error("the delete with a wrong key removed the object")
	}
	// no p_max is a limit of 0 and not none (#273)
	nomax, _ := http.NewRequest("POST", url+"/rest/v1/rpc/sshr_get", strings.NewReader(`{"p_name":"`+name+`","p_max":null}`))
	nomax.Header.Set("Content-Type", "application/json")
	nomax.Header.Set("x-sshr-key", testKey)
	nomaxResp, err := http.DefaultClient.Do(nomax)
	must(t, err)
	nomaxBody, _ := io.ReadAll(nomaxResp.Body)
	nomaxResp.Body.Close()
	if !strings.Contains(string(nomaxBody), "PT413") {
		t.Errorf("get with a null p_max: %d %s", nomaxResp.StatusCode, nomaxBody)
	}
	// a caller without the key gets PT403 before any decoding (#272)
	bad, _ := http.NewRequest("POST", url+"/rest/v1/rpc/sshr_create", strings.NewReader(`{"p_name":"account","p_data":"!!!not base64"}`))
	bad.Header.Set("Content-Type", "application/json")
	bad.Header.Set("x-sshr-key", strings.Repeat("cd", 32))
	badResp, err := http.DefaultClient.Do(bad)
	must(t, err)
	badBody, _ := io.ReadAll(badResp.Body)
	badResp.Body.Close()
	if !strings.Contains(string(badBody), "PT403") {
		t.Errorf("create with a wrong key and bad data: %d %s", badResp.StatusCode, badBody)
	}

	// the table is not reachable directly, authenticated cannot call
	for _, path := range []string{"/objects", "/keys"} {
		req, _ := http.NewRequest("GET", rest+path, nil)
		req.Header.Set("Accept-Profile", "sshr")
		resp, err := http.DefaultClient.Do(req)
		must(t, err)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("anon read %s of schema sshr", path)
		}
	}
	req, _ := http.NewRequest("POST", rest+"/rpc/sshr_get", strings.NewReader(`{"p_name":"account","p_max":10}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-sshr-key", testKey)
	req.Header.Set("Authorization", "Bearer "+hs256(secret, `{"role":"authenticated"}`))
	resp, err := http.DefaultClient.Do(req)
	must(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Errorf("authenticated called sshr_get: %d %s", resp.StatusCode, body)
	}
}

// two devices pair and sync through the real functions (#128)
func TestRealPostgresSync(t *testing.T) {
	url, _, _, _ := realREST(t)
	s, err := New(Config{URL: url, Key: pubKey}, testKey, nil)
	must(t, err)
	vault.SetKeychain(&memKeychain{m: map[string]string{}})
	vault.ResetForTest(filepath.Join(t.TempDir(), ".lock"))
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	mk := func(p string) *syncclient.Client {
		return &syncclient.Client{Store: &hosts.Store{Dir: t.TempDir()}, Dir: t.TempDir(), KeyPrefix: p,
			Backend: syncclient.ObjectBackend{Store: s}, Log: io.Discard}
	}
	a, b := mk("a-"), mk("b-")
	_, err = a.Store.Add(hosts.Host{Name: "web", Host: "10.0.0.1", User: "u", PasswordMode: hosts.PasswordSaved, Password: "pw"})
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
	list, _ := b.Store.List()
	if len(list) != 1 || list[0].Name != "web" {
		t.Fatalf("hosts on b %+v", list)
	}
	h := list[0]
	if err := hosts.UnlockSaved(&h); err != nil || h.Password != "pw" {
		t.Errorf("password on b %q %v", h.Password, err)
	}
}

// a key change keeps the old key working until the new one is in and
// then leaves only the new one (#274)
func TestRealPostgresReplaceKey(t *testing.T) {
	url, _, _, runSQL := realREST(t)
	old, err := New(Config{URL: url, Key: pubKey}, testKey, nil)
	must(t, err)
	must(t, old.Put("account", []byte("a")))
	newKey := strings.Repeat("ef", 32)
	runSQL(SetupSQL(newKey, true))
	fresh, err := New(Config{URL: url, Key: pubKey}, newKey, nil)
	must(t, err)
	if b, err := fresh.Get("account", 10); err != nil || string(b) != "a" {
		t.Errorf("the new key: %q %v", b, err)
	}
	if _, err := old.Get("account", 10); !errors.Is(err, ErrKeyRefused) {
		t.Errorf("the old key after a change: %v", err)
	}
}
