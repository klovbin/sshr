package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"sshr.dev/internal/app"
	"sshr.dev/internal/audit"
)

func do(t *testing.T, h http.Handler, method, path, body string, hdr map[string]string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, "http://127.0.0.1"+path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	b, _ := io.ReadAll(rec.Body)
	return rec.Code, string(b)
}

func TestAPIHosts(t *testing.T) {
	s := &app.Store{Dir: t.TempDir()}
	srv := New(s, Options{})
	code, body := do(t, srv, "POST", "/v1/hosts", `{"name":"web","host":"10.0.0.1","user":"u","ask_password":true,"forwards":["db -L 5432:localhost:5432"]}`, nil)
	if code != 201 || !strings.Contains(body, `"auth":"password asked every time`) {
		t.Fatalf("add = %d %s", code, body)
	}
	code, body = do(t, srv, "POST", "/v1/hosts", `{"host":"10.0.0.2","user":"u","password":"x"}`, nil)
	if code != 400 || !strings.Contains(body, "not taken through the API") {
		t.Errorf("add with a password = %d %s", code, body)
	}
	for _, f := range []string{"op_password", "op_key", "bw_password", "bw_key"} {
		code, body = do(t, srv, "POST", "/v1/hosts", `{"host":"10.0.0.2","user":"u","`+f+`":"op://v/i/password"}`, nil)
		if code != 400 || !strings.Contains(body, "references are not taken") {
			t.Errorf("add with %s = %d %s", f, code, body)
		}
	}
	code, body = do(t, srv, "POST", "/v1/hosts", `{"host":"10.0.0.2","user":"u","bogus":1}`, nil)
	if code != 400 {
		t.Errorf("unknown field = %d %s", code, body)
	}
	code, body = do(t, srv, "GET", "/v1/hosts", "", nil)
	var hosts []app.HostSummary
	if code != 200 || json.Unmarshal([]byte(body), &hosts) != nil || len(hosts) != 1 || hosts[0].Forwards[0] != "db -L 5432:localhost:5432" {
		t.Errorf("list = %d %s", code, body)
	}
	if code, _ = do(t, srv, "GET", "/v1/hosts/nope", "", nil); code != 404 {
		t.Errorf("unknown host = %d", code)
	}
	code, body = do(t, srv, "GET", "/v1/hosts/web/connect", "", nil)
	if code != 200 || !strings.Contains(body, `"connect","`+hosts[0].ID+`"`) {
		t.Errorf("connect = %d %s", code, body)
	}
	if code, body = do(t, srv, "POST", "/v1/hosts/web/run", `{"command":"id"}`, nil); code != 403 {
		t.Errorf("run while off = %d %s", code, body)
	}
	for _, bad := range []string{`{"forwards": "db"}`, `{"forwards": [`} {
		if code, body = do(t, srv, "POST", "/v1/hosts/web/tunnels", bad, nil); code != 400 || !strings.Contains(body, "bad body") {
			t.Errorf("tunnel with body %s = %d %s", bad, code, body)
		}
	}
	if code, body = do(t, srv, "POST", "/v1/hosts/web/tunnels", `{}`, nil); code != 400 || !strings.Contains(body, "asks_password") {
		t.Errorf("tunnel to an ask host = %d %s", code, body)
	}
	if code, _ = do(t, srv, "DELETE", "/v1/hosts/web", "", nil); code != 204 {
		t.Errorf("delete = %d", code)
	}
}

func TestAPIGuard(t *testing.T) {
	srv := New(&app.Store{Dir: t.TempDir()}, Options{Token: "tok"})
	if code, _ := do(t, srv, "GET", "/v1/hosts", "", nil); code != 401 {
		t.Errorf("no token = %d", code)
	}
	if code, _ := do(t, srv, "GET", "/v1/hosts", "", map[string]string{"Authorization": "Bearer bad"}); code != 401 {
		t.Errorf("bad token = %d", code)
	}
	if code, _ := do(t, srv, "GET", "/v1/hosts", "", map[string]string{"Authorization": "Bearer tok"}); code != 200 {
		t.Errorf("good token = %d", code)
	}
	if code, _ := do(t, srv, "GET", "/v1/hosts", "", map[string]string{"Authorization": "Bearer tok", "Origin": "http://evil.example"}); code != 403 {
		t.Errorf("request from a page = %d", code)
	}
	req := httptest.NewRequest("GET", "http://evil.example/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Errorf("rebinding host = %d", rec.Code)
	}
	// only loopback addresses, the API is not for the network (#197)
	for host, want := range map[string]int{"192.168.1.5:7000": 403, "0.0.0.0:7000": 403, "[::1]:7000": 200, "127.0.0.1:7000": 200} {
		req := httptest.NewRequest("GET", "http://"+host+"/v1/hosts", nil)
		req.Header.Set("Authorization", "Bearer tok")
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Host %s = %d, want %d", host, rec.Code, want)
		}
	}
}

func TestAPIUploadAndTunnelChecks(t *testing.T) {
	s := &app.Store{Dir: t.TempDir()}
	srv := New(s, Options{})
	if _, err := s.Add(app.Host{Name: "web", Host: "10.0.0.1", User: "u"}); err != nil {
		t.Fatal(err)
	}
	for _, ext := range []string{"sh%3Bid", "a%24b", "a/b", "a%20b", "abcdefghijk"} {
		if code, body := do(t, srv, "POST", "/v1/hosts/web/upload?ext="+ext, "data", nil); code != 400 || !strings.Contains(body, "ext must be") {
			t.Errorf("upload with ext %q = %d %s", ext, code, body)
		}
	}
	if code, body := do(t, srv, "POST", "/v1/hosts/web/tunnels", "", nil); code != 400 || !strings.Contains(body, "no saved forwards") {
		t.Errorf("tunnel of a host without forwards = %d %s", code, body)
	}
}

// a tunnel opened through the API runs ssh in batch mode with the options
// it has always had, an ssh that fails at once is reported with its error
func TestAPITunnelCommandLine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake ssh is a shell script")
	}
	bin := t.TempDir()
	log := filepath.Join(bin, "ssh.log")
	script := "#!/bin/sh\necho \"batch=$SSHR_BATCH $*\" > " + log + "\necho 'bind: Address already in use' >&2\nexit 255\n"
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	s := &app.Store{Dir: t.TempDir()}
	if _, err := s.Add(app.Host{Name: "web", Host: "10.0.0.1", User: "u", Key: "/k", Forwards: []app.Forward{{Name: "db", Kind: "L", Spec: "5432:localhost:5432"}}}); err != nil {
		t.Fatal(err)
	}
	code, body := do(t, New(s, Options{}), "POST", "/v1/hosts/web/tunnels", "", nil)
	if code != 502 || !strings.Contains(body, "did not open: bind: Address already in use") {
		t.Errorf("tunnel = %d %s", code, body)
	}
	got, _ := os.ReadFile(log)
	want := "batch=1 -i /k -p 22 -o BatchMode=yes -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -L 5432:localhost:5432 -- u@10.0.0.1\n"
	if string(got) != want {
		t.Errorf("ssh ran\n%q\nwant\n%q", got, want)
	}
}

// uploads and commands take one of maxRunning slots, the next one waits
// until a slot is free or its client goes away (#101)
func TestAPIRunLimit(t *testing.T) {
	a := &api{slots: make(chan struct{}, maxRunning)}
	for i := 0; i < maxRunning; i++ {
		a.slots <- struct{}{}
	}
	ran := false
	h := a.limit(func(w http.ResponseWriter, r *http.Request) { ran = true })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest("POST", "/v1/hosts/web/run", nil).WithContext(ctx))
	if ran || rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a ninth request ran: %v %d", ran, rec.Code)
	}
	<-a.slots
	h(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/hosts/web/run", nil))
	if !ran || len(a.slots) != maxRunning-1 {
		t.Fatalf("a free slot was not used or not given back: %v %d", ran, len(a.slots))
	}
}

// the command in the log is quoted, control characters in it cannot
// rewrite the terminal or the log (#200)
func TestAPIRunLogQuoted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake ssh is a shell script")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ssh"), []byte("#!/bin/sh\necho ok\n"), 0o700)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	var log strings.Builder
	old := logOut
	logOut = &log
	t.Cleanup(func() { logOut = old })
	s := &app.Store{Dir: t.TempDir()}
	s.Add(app.Host{Name: "web", Host: "10.0.0.1", User: "u"})
	body := `{"command":"id\r\u001b[2Kfake\nsshr serve: run on web: ok"}`
	if code, out := do(t, New(s, Options{AllowCommands: true}), "POST", "/v1/hosts/web/run", body, nil); code != 200 {
		t.Fatalf("run = %d %s", code, out)
	}
	if out := log.String(); strings.ContainsAny(out, "\r\x1b") || strings.Count(out, "\n") != 1 {
		t.Fatalf("control characters reach the log: %q", out)
	}
}

// a host the command policy refuses gets 403 (#101)
func TestAPIRunPolicy(t *testing.T) {
	s := &app.Store{Dir: t.TempDir()}
	s.Add(app.Host{Name: "web", Host: "10.0.0.1", User: "u"})
	srv := New(s, Options{AllowCommands: true, CommandsAllowed: func(*app.Host) error { return app.ErrCommandsNotAllowed }})
	if code, out := do(t, srv, "POST", "/v1/hosts/web/run", `{"command":"id"}`, nil); code != 403 {
		t.Fatalf("run = %d %s", code, out)
	}
}

// a request whose client went away while it waited for a slot does not
// run (#207)
func TestAPIGoneClientDoesNotRun(t *testing.T) {
	a := &api{slots: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec := httptest.NewRecorder()
	if _, ok := a.take(rec, httptest.NewRequest("POST", "/v1/hosts/web/run", nil).WithContext(ctx)); ok || rec.Code != 503 || len(a.slots) != 0 {
		t.Fatalf("a gone client got a slot: %v %d %d", ok, rec.Code, len(a.slots))
	}
}

// the audit end of a tunnel is written when ssh exits, with its exit
// code, not when the request is answered (#208)
func TestAPITunnelAuditEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake ssh is a shell script")
	}
	bin := t.TempDir()
	os.WriteFile(filepath.Join(bin, "ssh"), []byte("#!/bin/sh\nsleep 3\nexit 3\n"), 0o700)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	s := &app.Store{Dir: t.TempDir()}
	s.Add(app.Host{Name: "web", Host: "10.0.0.1", User: "u", Key: "/k", Forwards: []app.Forward{{Name: "db", Kind: "L", Spec: "5432:localhost:5432"}}})
	dir := t.TempDir()
	l, err := audit.Open(dir, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := do(t, New(s, Options{Audit: l}), "POST", "/v1/hosts/web/tunnels", "", nil); code != 201 {
		t.Fatalf("tunnel = %d %s", code, body)
	}
	path := filepath.Join(dir, audit.FileName)
	if b, _ := os.ReadFile(path); strings.Count(string(b), "\n") != 1 {
		t.Fatalf("an end was written while the tunnel runs: %s", b)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		b, _ := os.ReadFile(path)
		if strings.Count(string(b), "\n") == 2 {
			if !strings.Contains(string(b), `"exit":3`) {
				t.Fatalf("end without the exit code of ssh: %s", b)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no end after ssh exited: %s", b)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
