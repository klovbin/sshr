package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sshr.dev/internal/app"
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
}
