package app

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestPickSSH checks which ssh sshr runs (#154): on Windows the ssh of Git
// for Windows on PATH gives way to the OpenSSH of Windows when it is
// there, elsewhere the first ssh on PATH is taken
func TestPickSSH(t *testing.T) {
	gitSSH := `C:\Program Files\Git\usr\bin\ssh.exe`
	system := filepath.Join(`C:\Windows`, "System32", "OpenSSH", "ssh.exe")
	scoop := `C:\Users\u\scoop\shims\ssh.exe`
	look := func(p string) func(string) (string, error) {
		return func(string) (string, error) {
			if p == "" {
				return "", errors.New("not found")
			}
			return p, nil
		}
	}
	// the system ssh and the runtime of an msys or cygwin ssh exist, nothing else
	has := func(ok bool) func(string) bool {
		return func(p string) bool {
			if strings.HasSuffix(p, "msys-2.0.dll") {
				return strings.Contains(p, `Git`) || strings.Contains(p, `Portable`)
			}
			if dir, ok := strings.CutSuffix(p, "cygwin1.dll"); ok {
				return strings.Contains(dir, "cygwin")
			}
			return ok
		}
	}
	for _, c := range []struct {
		name, goos, path string
		system           bool
		want             string
		fails            bool
	}{
		{"linux", "linux", "/usr/bin/ssh", false, "/usr/bin/ssh", false},
		{"linux none", "linux", "", false, "", true},
		{"windows git ssh, system there", "windows", gitSSH, true, system, false},
		{"windows git ssh only", "windows", gitSSH, false, gitSSH, false},
		{"windows other ssh first", "windows", scoop, true, scoop, false},
		{"windows only system", "windows", "", true, system, false},
		{"windows portable git", "windows", `D:\Portable\usr\bin\ssh.exe`, true, system, false},
		{"windows cygwin", "windows", `C:\cygwin64\bin\ssh.exe`, true, system, false},
		{"windows none", "windows", "", false, "", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := pickSSH(c.goos, look(c.path), `C:\Windows`, has(c.system))
			if (err != nil) != c.fails || got != c.want {
				t.Fatalf("got %q, %v, want %q", got, err, c.want)
			}
		})
	}
}

func TestParseSSHVersion(t *testing.T) {
	for out, want := range map[string][3]int{
		"OpenSSH_9.6p1, OpenSSL 3.0.13 30 Jan 2024": {9, 6, 1},
		"OpenSSH_for_Windows_8.1p1, LibreSSL 3.0.2": {8, 1, 1},
		"OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2": {9, 5, 1},
		"Dropbear v2022.83":                         {0, 0, 0},
	} {
		ma, mi, ok := parseSSHVersion(out)
		okInt := 0
		if ok {
			okInt = 1
		}
		if [3]int{ma, mi, okInt} != want {
			t.Errorf("%q: %d.%d %v", out, ma, mi, ok)
		}
	}
}

// TestAskpassSupported checks that a saved password is refused for an
// ssh older than 8.4 with a reason, a newer or unknown one is let through
func TestAskpassSupported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake ssh is a shell script")
	}
	dir := t.TempDir()
	fake := func(name, version string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("#!/bin/sh\necho '"+version+"' >&2\n"), 0o700)
		return p
	}
	if err := askpassSupported(fake("old", "OpenSSH_8.1p1, OpenSSL 1.1.1")); err == nil || !strings.Contains(err.Error(), "8.4") {
		t.Errorf("old ssh: %v", err)
	}
	if err := askpassSupported(fake("new", "OpenSSH_9.6p1, OpenSSL 3.0")); err != nil {
		t.Errorf("new ssh: %v", err)
	}
	if err := askpassSupported(fake("other", "Dropbear v2022")); err != nil {
		t.Errorf("unknown ssh: %v", err)
	}
}

// TestNoBareSSH checks that no code of the package or the CLI starts "ssh"
// by name, every call takes the ssh of SSHPath (#312)
func TestNoBareSSH(t *testing.T) {
	for _, dir := range []string{".", "../../cmd/sshr"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, bad := range []string{`exec.Command("ssh"`, `exec.CommandContext(ctx, "ssh"`, `LookPath("ssh")`} {
				if strings.Contains(string(b), bad) && !strings.HasSuffix(f, "sshbin.go") {
					t.Errorf("%s starts ssh by name (%s), use sshCommand or SSHPath", f, bad)
				}
			}
		}
	}
}

// TestChildSSH checks the ssh scp and mosh are told to use (#313, #316):
// the chosen one on Windows, the one of SSHR_SSH anywhere, a path with
// spaces goes to scp but not to mosh
func TestChildSSH(t *testing.T) {
	sys := func() (string, error) { return `C:\Windows\System32\OpenSSH\ssh.exe`, nil }
	spaced := func() (string, error) { return `C:\Program Files\Git\usr\bin\ssh.exe`, nil }
	own := func() (string, error) { return "/opt/ssh9/bin/ssh", nil }
	for _, c := range []struct {
		name, goos, own string
		path            func() (string, error)
		mosh            bool
		want            string
	}{
		{"windows", "windows", "", sys, true, `C:\Windows\System32\OpenSSH\ssh.exe`},
		{"linux", "linux", "", sys, true, ""},
		{"linux SSHR_SSH", "linux", "/opt/ssh9/bin/ssh", own, false, "/opt/ssh9/bin/ssh"},
		{"spaces for scp", "windows", `C:\Program Files\Git\usr\bin\ssh.exe`, spaced, false, `C:\Program Files\Git\usr\bin\ssh.exe`},
		{"spaces for mosh", "windows", `C:\Program Files\Git\usr\bin\ssh.exe`, spaced, true, ""},
	} {
		if got := childSSH(c.goos, c.path, c.own, c.mosh); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// TestSSHROwnSSH checks that SSHR_SSH names the ssh to run (#314)
func TestSSHROwnSSH(t *testing.T) {
	own := filepath.Join(t.TempDir(), "my-ssh")
	os.WriteFile(own, []byte("x"), 0o700)
	t.Setenv("SSHR_SSH", own)
	if p, err := SSHPath(); err != nil || p != own {
		t.Fatalf("SSHR_SSH: %q %v", p, err)
	}
	t.Setenv("SSHR_SSH", own+"-missing")
	if _, err := SSHPath(); err == nil {
		t.Fatal("a missing SSHR_SSH went through")
	}
}

// TestSSHVersionTimeoutAndUpdate checks that an ssh -V that hangs counts
// as unknown after the timeout and that an ssh updated in place is read
// again (#315)
func TestSSHVersionTimeoutAndUpdate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake ssh is a shell script")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "ssh")
	os.WriteFile(p, []byte("#!/bin/sh\necho 'OpenSSH_8.1p1' >&2\n"), 0o700)
	if ma, mi, ok := sshVersion(p); !ok || ma != 8 || mi != 1 {
		t.Fatalf("first read %d.%d %v", ma, mi, ok)
	}
	os.WriteFile(p, []byte("#!/bin/sh\necho 'OpenSSH_9.6p1 newer' >&2\n"), 0o700)
	if ma, mi, ok := sshVersion(p); !ok || ma != 9 || mi != 6 {
		t.Fatalf("after the update %d.%d %v", ma, mi, ok)
	}
	slow := filepath.Join(dir, "slow")
	os.WriteFile(slow, []byte("#!/bin/sh\nsleep 10\n"), 0o700)
	start := time.Now()
	if _, _, ok := sshVersion(slow); ok || time.Since(start) > sshVersionTimeout+2*time.Second {
		t.Fatalf("a hanging ssh -V: ok %v after %s", ok, time.Since(start))
	}
}
