package sshcmd

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCapWriter(t *testing.T) {
	w := &capWriter{max: 10}
	w.Write([]byte("12345"))
	w.Write([]byte("67890"))
	if w.buf.String() != "1234567890" || w.over {
		t.Fatalf("at the limit: %q over=%v", w.buf.String(), w.over)
	}
	if n, _ := w.Write([]byte("x")); n != 1 || !w.over || w.buf.Len() != 10 {
		t.Fatalf("over the limit: n=%d %q over=%v", n, w.buf.String(), w.over)
	}
	w = &capWriter{max: 4}
	w.Write([]byte("abcdef"))
	if w.buf.String() != "abcd" || !w.over {
		t.Fatalf("one write across the limit: %q over=%v", w.buf.String(), w.over)
	}
}

func TestRemoteTimeoutScriptQuoting(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	// the wrapper runs here the way the server runs it, with quotes and a
	// dollar sign in the command, which must reach sh untouched
	command := `printf '%s\n' "it's" '$HOME'`
	remote := "sh -c " + shQuote(remoteTimeoutScript(5)) + " sshr " + shQuote(command)
	out, err := exec.Command("sh", "-c", remote).Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "it's\n$HOME\n" {
		t.Fatalf("output = %q", out)
	}
}

func TestRunRemoteAsksPassword(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	_, err := s.RunRemote(&Host{Name: "w", Host: "10.0.0.1", User: "u", PasswordMode: PasswordAsk}, "id", nil, time.Second)
	if _, lerr := exec.LookPath("ssh"); lerr == nil && !errors.Is(err, ErrAsksPassword) {
		t.Fatalf("RunRemote on an ask host = %v", err)
	}
}

func TestRunRemoteKeepsOutputOfAStoppedCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake ssh is a shell script")
	}
	// a fake ssh that prints, then exits as timeout(1) does
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ssh"), []byte("#!/bin/sh\necho started\nexit 124\n"), 0o700)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	s := &Store{Dir: t.TempDir()}
	res, err := s.RunRemote(&Host{Name: "w", Host: "10.0.0.1", User: "u"}, "sleep 9", nil, time.Second)
	if err == nil || res == nil || !strings.Contains(string(res.Stdout), "started") || res.ExitCode != 124 {
		t.Fatalf("res %+v err %v", res, err)
	}
}
