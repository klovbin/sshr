package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"sshr.dev/internal/app"
)

// exchange sends one request per line and returns the answers by id
func exchange(t *testing.T, store *app.Store, opts Options, lines ...string) map[string]map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := Serve(strings.NewReader(strings.Join(lines, "\n")+"\n"), &out, store, opts); err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]any{}
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("bad answer %q: %v", l, err)
		}
		id, _ := json.Marshal(m["id"])
		got[string(id)] = m
	}
	return got
}

func toolNames(m map[string]any) []string {
	var names []string
	for _, t := range m["result"].(map[string]any)["tools"].([]any) {
		names = append(names, t.(map[string]any)["name"].(string))
	}
	return names
}

func TestServe(t *testing.T) {
	s := &app.Store{Dir: t.TempDir()}
	if _, err := s.Add(app.Host{Name: "web", Host: "10.0.0.1", User: "u", PasswordMode: app.PasswordAsk, Jump: "bastion"}); err != nil {
		t.Fatal(err)
	}
	got := exchange(t, s, Options{},
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_hosts","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run_command","arguments":{"host":"web","command":"id"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"nope"}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"upload_file","arguments":{"host":"nope","path":"/etc/hostname"}}}`,
		`{"jsonrpc":"2.0","id":"x","method":"initialize","params":{"protocolVersion":"1999-01-01"}}`,
	)
	if len(got) != 7 {
		t.Fatalf("answers = %d, want 7 (no answer to the notification)", len(got))
	}
	if v := got["1"]["result"].(map[string]any)["protocolVersion"]; v != "2025-06-18" {
		t.Errorf("negotiated %v", v)
	}
	if v := got[`"x"`]["result"].(map[string]any)["protocolVersion"]; v != versions[0] {
		t.Errorf("unknown version answered with %v", v)
	}
	if names := strings.Join(toolNames(got["2"]), ","); names != "list_hosts,upload_file" {
		t.Errorf("tools = %s", names)
	}
	text := got["3"]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, `"name": "web"`) || !strings.Contains(text, "bastion") || !strings.Contains(text, "asked every time") {
		t.Errorf("list_hosts = %s", text)
	}
	if got["4"]["error"] == nil {
		t.Error("run_command answered while commands are off")
	}
	if got["5"]["error"].(map[string]any)["code"].(float64) != -32601 {
		t.Errorf("unknown method = %v", got["5"])
	}
	if r := got["6"]["result"].(map[string]any); r["isError"] != true {
		t.Errorf("upload to an unknown host = %v", r)
	}
}

func TestRunCommandOffered(t *testing.T) {
	s := &app.Store{Dir: t.TempDir()}
	s.Add(app.Host{Name: "web", Host: "10.0.0.1", User: "u", PasswordMode: app.PasswordAsk})
	got := exchange(t, s, Options{AllowCommands: true},
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_command","arguments":{"host":"web","command":"id"}}}`,
	)
	if names := strings.Join(toolNames(got["1"]), ","); names != "list_hosts,upload_file,run_command" {
		t.Errorf("tools = %s", names)
	}
	// a host that asks for its password has nobody to ask here
	r := got["2"]["result"].(map[string]any)
	if r["isError"] != true {
		t.Errorf("run on an ask host = %v", r)
	}
}

func TestRunCommandLimit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake ssh is a shell script")
	}
	dir := t.TempDir()
	runs := filepath.Join(dir, "runs")
	os.Mkdir(runs, 0o700)
	// the fake ssh notes how many copies of it run at once
	script := "#!/bin/sh\nmkdir " + runs + "/$$\nls " + runs + " | wc -l >> " + dir + "/seen\nsleep 0.3\nrmdir " + runs + "/$$\n"
	os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o700)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	s := &app.Store{Dir: t.TempDir()}
	s.Add(app.Host{Name: "web", Host: "10.0.0.1", User: "u"})
	var lines []string
	for i := 0; i < 3*maxRunning; i++ {
		lines = append(lines, `{"jsonrpc":"2.0","id":`+strconv.Itoa(i)+`,"method":"tools/call","params":{"name":"run_command","arguments":{"host":"web","command":"id"}}}`)
	}
	exchange(t, s, Options{AllowCommands: true}, lines...)
	b, _ := os.ReadFile(filepath.Join(dir, "seen"))
	most := 0
	for _, f := range strings.Fields(string(b)) {
		if n, _ := strconv.Atoi(f); n > most {
			most = n
		}
	}
	if most == 0 || most > maxRunning {
		t.Fatalf("at most %d commands ran at once, the limit is %d", most, maxRunning)
	}
}

func TestUploadRefusesHiddenFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	key := filepath.Join(home, ".ssh", "id_ed25519")
	os.WriteFile(key, []byte("secret"), 0o600)
	os.WriteFile(filepath.Join(home, ".sshr-token"), []byte("t"), 0o600)
	paths := []string{key, filepath.Join(home, ".sshr-token")}
	// a link to a key is refused too, Windows may not allow making one
	if link := filepath.Join(home, "notes.txt"); os.Symlink(key, link) == nil {
		paths = append(paths, link)
	}
	for _, p := range paths {
		if err := checkUploadPath(p); err == nil || !strings.Contains(err.Error(), "hidden") {
			t.Errorf("checkUploadPath(%s) = %v", p, err)
		}
	}
	ok := filepath.Join(home, "shot.png")
	os.WriteFile(ok, []byte("png"), 0o600)
	if err := checkUploadPath(ok); err != nil {
		t.Errorf("a plain file was refused: %v", err)
	}
}

func resultText(t *testing.T, m map[string]any) (string, bool) {
	t.Helper()
	r, ok := m["result"].(map[string]any)
	if !ok {
		return fmt.Sprint(m["error"]), true
	}
	text := ""
	if c, ok := r["content"].([]any); ok && len(c) > 0 {
		text, _ = c[0].(map[string]any)["text"].(string)
	}
	return text, r["isError"] == true
}

func TestUploadFileArguments(t *testing.T) {
	s := &app.Store{Dir: t.TempDir()}
	s.Add(app.Host{Name: "a", Host: "10.0.0.1", User: "u", PasswordMode: app.PasswordAsk})
	s.Add(app.Host{Name: "b", Host: "10.0.0.1", User: "u", PasswordMode: app.PasswordAsk})
	dir := t.TempDir()
	call := func(id int, host, path string) string {
		return `{"jsonrpc":"2.0","id":` + strconv.Itoa(id) + `,"method":"tools/call","params":{"name":"upload_file","arguments":{"host":"` + host + `","path":` + strconv.Quote(path) + `}}}`
	}
	got := exchange(t, s, Options{}, call(1, "a", "relative.txt"), call(2, "a", dir), call(3, "10.0.0.1", "/etc/hostname"))
	for id, want := range map[string]string{"1": "absolute", "2": "regular file", "3": "several"} {
		if text, isErr := resultText(t, got[id]); !isErr || !strings.Contains(text, want) {
			t.Errorf("call %s = %q, want an error with %q", id, text, want)
		}
	}
}

func TestRunCommandTimeoutClamp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake ssh is a shell script")
	}
	dir := t.TempDir()
	// the fake ssh prints the remote command it got
	os.WriteFile(filepath.Join(dir, "ssh"), []byte("#!/bin/sh\nfor a; do last=$a; done\necho \"$last\"\n"), 0o700)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	s := &app.Store{Dir: t.TempDir()}
	s.Add(app.Host{Name: "web", Host: "10.0.0.1", User: "u"})
	call := func(id, secs int) string {
		return `{"jsonrpc":"2.0","id":` + strconv.Itoa(id) + `,"method":"tools/call","params":{"name":"run_command","arguments":{"host":"web","command":"id","timeout_seconds":` + strconv.Itoa(secs) + `}}}`
	}
	got := exchange(t, s, Options{AllowCommands: true}, call(1, 99999), call(2, 0), call(3, 30))
	for id, want := range map[string]string{"1": "timeout -k 5 600 ", "2": "timeout -k 5 60 ", "3": "timeout -k 5 30 "} {
		b, _ := json.Marshal(got[id])
		if !strings.Contains(string(b), want) {
			t.Errorf("call %s: no %q in %s", id, want, b)
		}
	}
}

func TestToolErrorWordsAsksPassword(t *testing.T) {
	s := &app.Store{Dir: t.TempDir()}
	if _, err := s.Add(app.Host{Name: "web", Host: "10.0.0.1", User: "u", PasswordMode: app.PasswordAsk}); err != nil {
		t.Fatal(err)
	}
	got := exchange(t, s, Options{AllowCommands: true},
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_command","arguments":{"host":"web","command":"id"}}}`)
	res := got["1"]["result"].(map[string]any)
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if res["isError"] != true || !strings.Contains(text, "asks for its password") {
		t.Fatalf("result = %v, want a sentence about the password", res)
	}
}
