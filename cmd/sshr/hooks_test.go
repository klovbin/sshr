package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLocalCommands checks the commands that run on this machine around
// sshr connect (#29): off by default, on with the setting or the flag, a
// failing command before stops the connect, the one after gets the exit
// code of the session
func TestLocalCommands(t *testing.T) {
	tools := fakeTools(t)
	home := t.TempDir()
	log := filepath.Join(t.TempDir(), "log")
	mustRun(t, home, "add", "10.0.0.5", "-u", "deploy", "-n", "web", "--ask-password")
	mustRun(t, home, "hooks", "set", "web", "before", `echo "before $SSHR_HOST_NAME $SSHR_HOST $SSHR_PORT" >>`+log)
	mustRun(t, home, "hooks", "set", "web", "after", `echo "after $SSHR_EXIT" >>`+log)
	os.WriteFile(filepath.Join(tools, "ssh.code"), []byte("7"), 0o600)
	readLog := func() string {
		b, _ := os.ReadFile(log)
		os.Remove(log)
		return string(b)
	}

	_, errOut, code := sshrIn(t, home, "connect", "--plain", "web")
	if code != 7 || readLog() != "" || argsOf(t, tools, "ssh") == "" || !strings.Contains(errOut, "has local commands, they are off") {
		t.Errorf("off by default: %d %q", code, errOut)
	}

	_, errOut, code = sshrIn(t, home, "connect", "--plain", "--local-commands", "web")
	if got := readLog(); code != 7 || got != "before web 10.0.0.5 22\nafter 7\n" || argsOf(t, tools, "ssh") == "" {
		t.Errorf("--local-commands: %d %q %q", code, got, errOut)
	}

	mustRun(t, home, "hooks", "on")
	_, _, code = sshrIn(t, home, "connect", "--plain", "--no-local-commands", "web")
	if code != 7 || readLog() != "" || argsOf(t, tools, "ssh") == "" {
		t.Errorf("--no-local-commands ran them")
	}

	mustRun(t, home, "hooks", "set", "web", "before", "exit 3")
	_, errOut, code = sshrIn(t, home, "connect", "--plain", "web")
	if code != 1 || argsOf(t, tools, "ssh") != "" || readLog() != "" || !strings.Contains(errOut, "the command before connect failed") {
		t.Errorf("a failing command before: %d %q", code, errOut)
	}

	out, _, _ := sshrIn(t, home, "hooks", "list")
	if !strings.Contains(out, "Local commands: on") || !strings.Contains(out, "before: exit 3") {
		t.Errorf("list: %q", out)
	}
	mustRun(t, home, "hooks", "unset", "web", "before")
	mustRun(t, home, "rm", "web")
	b, err := os.ReadFile(filepath.Join(home, ".sshr", "settings.json"))
	if err != nil || strings.Contains(string(b), "host_commands") {
		t.Errorf("the commands of a removed host stay: %s %v", b, err)
	}
}
