package mcp

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"sshr.dev/internal/app"
)

// confirmRun calls run_command on a server that asks before commands, the
// client answers the question with reply(id), an empty answer closes
// stdin, it says whether ssh ran
func confirmRun(t *testing.T, version, caps string, reply func(id string) string) bool {
	t.Helper()
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	os.WriteFile(filepath.Join(dir, "ssh"), []byte("#!/bin/sh\ntouch "+marker+"\necho ok\n"), 0o700)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	s := &app.Store{Dir: t.TempDir()}
	s.Add(app.Host{Name: "web", Host: "10.0.0.1", User: "u"})
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	served := make(chan struct{})
	go func() {
		Serve(inR, outW, s, Options{AllowCommands: true, ConfirmCommands: true})
		outW.Close()
		close(served)
	}()
	lines := bufio.NewScanner(outR)
	io.WriteString(inW, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+version+`","capabilities":`+caps+`}}`+"\n")
	lines.Scan()
	io.WriteString(inW, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_command","arguments":{"host":"web","command":"systemctl restart web"}}}`+"\n")
	for lines.Scan() {
		var m map[string]json.RawMessage
		json.Unmarshal(lines.Bytes(), &m)
		if string(m["method"]) == `"elicitation/create"` {
			if !strings.Contains(string(m["params"]), `systemctl restart web`) {
				t.Errorf("the question does not show the command: %s", m["params"])
			}
			if r := reply(string(m["id"])); r != "" {
				io.WriteString(inW, r+"\n")
			} else {
				inW.Close()
			}
			continue
		}
		if string(m["id"]) == "2" {
			break
		}
	}
	inW.Close()
	go io.Copy(io.Discard, outR)
	<-served
	_, err := os.Stat(marker)
	return err == nil
}

// a command runs only after an explicit yes, every other answer, no answer
// and a client that cannot ask refuse it (#101)
func TestConfirmCommands(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake ssh is a shell script")
	}
	logOut = io.Discard
	t.Cleanup(func() { logOut = os.Stderr })
	answer := func(result string) func(string) string {
		return func(id string) string { return `{"jsonrpc":"2.0","id":` + id + `,"result":` + result + `}` }
	}
	elicit := `{"elicitation":{}}`
	for name, c := range map[string]struct {
		version, caps string
		reply         func(string) string
		want          bool
	}{
		"yes":            {"2025-06-18", elicit, answer(`{"action":"accept","content":{"run":true}}`), true},
		"form mode yes":  {"2025-11-25", `{"elicitation":{"form":{}}}`, answer(`{"action":"accept","content":{"run":true}}`), true},
		"unticked":       {"2025-06-18", elicit, answer(`{"action":"accept","content":{"run":false}}`), false},
		"decline":        {"2025-06-18", elicit, answer(`{"action":"decline"}`), false},
		"cancel":         {"2025-06-18", elicit, answer(`{"action":"cancel"}`), false},
		"error":          {"2025-06-18", elicit, func(id string) string { return `{"jsonrpc":"2.0","id":` + id + `,"error":{"code":-1,"message":"no"}}` }, false},
		"client gone":    {"2025-06-18", elicit, func(string) string { return "" }, false},
		"no capability":  {"2025-06-18", `{}`, answer(`{"action":"accept","content":{"run":true}}`), false},
		"url mode only":  {"2025-11-25", `{"elicitation":{"url":{}}}`, answer(`{"action":"accept","content":{"run":true}}`), false},
		"older protocol": {"2025-03-26", elicit, answer(`{"action":"accept","content":{"run":true}}`), false},
	} {
		if got := confirmRun(t, c.version, c.caps, c.reply); got != c.want {
			t.Errorf("%s: ran = %v, want %v", name, got, c.want)
		}
	}
}
