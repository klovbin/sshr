package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeSSHG puts an ssh in PATH that answers ssh -G with controlmaster v
func fakeSSHG(t *testing.T, v string) {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ssh"), []byte("#!/bin/sh\necho 'user u'\necho 'controlmaster "+v+"'\n"), 0o700)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestControlDirSkipsLongPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_RUNTIME_DIR", "/"+strings.Repeat("x", 80))
	dir, err := ControlDir()
	if len(home)+len("/.sshr/cm")+41 >= socketPathMax {
		if err == nil {
			t.Fatalf("a path too long for a socket was taken: %s", dir)
		}
		return
	}
	if err != nil || dir != filepath.Join(home, ".sshr", "cm") {
		t.Fatalf("ControlDir = %s %v", dir, err)
	}
	if fi, _ := os.Stat(dir); fi == nil || fi.Mode().Perm() != 0o700 && runtime.GOOS != "windows" {
		t.Fatalf("mode of %s = %v", dir, fi)
	}
}

func TestReuseArgs(t *testing.T) {
	if runtime.GOOS == "windows" {
		s := &Store{Dir: t.TempDir()}
		on := true
		s.Reuse = &on
		if args := s.reuseArgs(&Host{Host: "h", User: "u", Port: 22}); args != nil {
			t.Fatalf("reuse on Windows = %v", args)
		}
		return
	}
	dir, err := os.MkdirTemp("", "r")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	t.Setenv("XDG_RUNTIME_DIR", dir)
	h := &Host{Host: "h", User: "u", Port: 22}
	s := &Store{Dir: t.TempDir()}
	on, off := true, false

	fakeSSHG(t, "false")
	s.Reuse = &off
	if args := s.reuseArgs(h); args != nil {
		t.Errorf("reuse off = %v", args)
	}
	s.Reuse = &on
	if args := strings.Join(s.reuseArgs(h), " "); !strings.Contains(args, "ControlMaster=auto") || !strings.Contains(args, filepath.Join(dir, "sshr", "%C")) {
		t.Errorf("reuse on = %s", args)
	}
	s.Reuse = nil
	t.Setenv("SSHR_REUSE", "0")
	if args := s.reuseArgs(h); args != nil {
		t.Errorf("SSHR_REUSE=0 = %v", args)
	}
	// the user's own ControlMaster wins
	s.Reuse = &on
	fakeSSHG(t, "auto")
	if args := s.reuseArgs(h); args != nil {
		t.Errorf("with controlmaster auto in ssh config = %v", args)
	}
}
