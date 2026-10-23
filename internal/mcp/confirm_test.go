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

// the host shown in the question is the host the command runs on, a host
// repointed while the question waits does not get it (#212)
func TestConfirmRunsOnTheHostShown(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake ssh is a shell script")
	}
	logOut = io.Discard
	t.Cleanup(func() { logOut = os.Stderr })
	dir := t.TempDir()
	args := filepath.Join(dir, "args")
	os.WriteFile(filepath.Join(dir, "ssh"), []byte("#!/bin/sh\necho \"$*\" > "+args+"\necho ok\n"), 0o700)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	s := &app.Store{Dir: t.TempDir()}
	h, _ := s.Add(app.Host{Name: "web", Host: "10.0.0.1", User: "u"})
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	served := make(chan struct{})
	go func() {
		Serve(inR, outW, s, Options{AllowCommands: true, ConfirmCommands: true})
		outW.Close()
		close(served)
	}()
	lines := bufio.NewScanner(outR)
	io.WriteString(inW, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"elicitation":{}}}}`+"\n")
	lines.Scan()
	io.WriteString(inW, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_command","arguments":{"host":"web","command":"uptime"}}}`+"\n")
	for lines.Scan() {
		var m map[string]json.RawMessage
		json.Unmarshal(lines.Bytes(), &m)
		if string(m["method"]) == `"elicitation/create"` {
			// another device repoints the host while the user reads
			moved := *h
			moved.Host = "evil.example"
			if _, err := s.Update(h.ID, moved); err != nil {
				t.Fatal(err)
			}
			io.WriteString(inW, `{"jsonrpc":"2.0","id":`+string(m["id"])+`,"result":{"action":"accept","content":{"run":true}}}`+"\n")
			continue
		}
		if string(m["id"]) == "2" {
			break
		}
	}
	inW.Close()
	go io.Copy(io.Discard, outR)
	<-served
	b, _ := os.ReadFile(args)
	if strings.Contains(string(b), "evil.example") || !strings.Contains(string(b), "10.0.0.1") {
		t.Fatalf("ssh ran with %q", b)
	}
}

// a destination with control characters is cleaned in the question, a
// command too long to show in full is refused without a question (#215)
func TestConfirmQuestionText(t *testing.T) {
	s := &server{elicit: true, pending: map[string]chan request{}, done: make(chan struct{}), w: io.Discard}
	h := &app.Host{Name: "web", Host: "10.0.0.1", User: "u"}
	if err := s.confirm(h, strings.Repeat("x", confirmMax+1)); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("a long command: %v", err)
	}
	var out strings.Builder
	s.w = &out
	h.User = "u‮\x1b[8m"
	close(s.done)
	s.confirm(h, "uptime")
	if strings.Contains(out.String(), `‮`) || strings.Contains(out.String(), `\u001b`) {
		t.Fatalf("question: %s", out.String())
	}
}
