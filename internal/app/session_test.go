package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSessionScript(t *testing.T) {
	if !strings.Contains(SessionScript(SessionTmux), "tmux new-session -A -s sshr") {
		t.Error("tmux script")
	}
	if !strings.Contains(SessionScript(SessionZellij), "zellij attach --create sshr") {
		t.Error("zellij script")
	}
	if SessionScript("screen") != "" || SessionCommand("") != "" {
		t.Error("an unknown or empty session gives a script")
	}
	if checkSession("screen") == nil || checkSession(SessionTmux) != nil {
		t.Error("checkSession")
	}
}

// the command runs where ssh hands it to the login shell, sh and fish
// here, without tmux it falls back to the shell with a message
func TestSessionCommandInShells(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	if runtime.GOOS == "windows" {
		t.Skip("the fake login shell is a shell script")
	}
	empty := t.TempDir()
	os.Symlink(sh, filepath.Join(empty, "sh"))
	login := filepath.Join(empty, "login")
	os.WriteFile(login, []byte("#!/bin/sh\necho login shell \"$1\"\n"), 0o700)
	for _, shell := range []string{"sh", "fish"} {
		bin, err := exec.LookPath(shell)
		if err != nil {
			continue
		}
		args := []string{"-c", SessionCommand(SessionTmux)}
		if shell == "fish" {
			// the user's fish config would add its own PATH
			args = append([]string{"--no-config"}, args...)
		}
		cmd := exec.Command(bin, args...)
		// no tmux in PATH, the fallback runs SHELL as a login shell
		cmd.Env = []string{"PATH=" + empty, "SHELL=" + login, "HOME=" + empty}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v %s", shell, err, out)
		}
		if !strings.Contains(string(out), "tmux is not installed") || !strings.Contains(string(out), "login shell -l") {
			t.Errorf("%s: %q", shell, out)
		}
	}
}
