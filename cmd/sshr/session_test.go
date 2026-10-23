package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeTools puts ssh and mosh on PATH that write their arguments, one per
// line, to <name>.args in dir and exit with the code in <name>.code
func fakeTools(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake ssh and mosh are shell scripts")
	}
	dir := t.TempDir()
	for _, name := range []string{"ssh", "mosh"} {
		script := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > " + filepath.Join(dir, name+".args") +
			"\ncode=0\n[ -f " + filepath.Join(dir, name+".code") + " ] && code=$(cat " + filepath.Join(dir, name+".code") + ")\nexit $code\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

// argsOf is what the fake tool was called with, empty when it did not run
func argsOf(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name+".args"))
	if err != nil {
		return ""
	}
	os.Remove(filepath.Join(dir, name+".args"))
	return strings.Join(strings.Split(strings.TrimSpace(string(b)), "\n"), " ")
}

func mustRun(t *testing.T, home string, args ...string) {
	t.Helper()
	if out, errOut, code := sshrIn(t, home, args...); code != 0 {
		t.Fatalf("sshr %v: %d %s %s", args, code, out, errOut)
	}
}

// The command lines and messages of connect and tunnel, fixed before the
// session start moves into the core (#96), a change here changes what the
// user's ssh runs
func TestConnectCommandLines(t *testing.T) {
	tools := fakeTools(t)
	home := t.TempDir()
	mustRun(t, home, "add", "10.0.0.5", "-u", "deploy", "-n", "web", "--ask-password", "--session", "tmux")
	mustRun(t, home, "forward", "add", "web", "db", "-L", "5432:localhost:5432")
	mustRun(t, home, "add", "10.0.0.6", "-u", "app", "-n", "inner", "--ask-password", "-J", "ops@gw:2222")
	const ask = "-o PreferredAuthentications=keyboard-interactive,password -o PubkeyAuthentication=no -p 22"
	const tmux = `if command -v tmux >/dev/null 2>&1; then exec tmux new-session -A -s sshr; fi echo "sshr: tmux is not installed on this server, opening a plain shell" >&2 exec "${SHELL:-/bin/sh}" -l`

	for _, c := range []struct {
		name, ssh, mosh, out, errOut string
		args                         []string
		code                         int
	}{
		{name: "session", args: []string{"connect", "web"},
			ssh: ask + " -t -- deploy@10.0.0.5 sh -c '" + tmux + "'",
			out: "Connecting to web (deploy@10.0.0.5:22), tmux session sshr...\n"},
		{name: "plain", args: []string{"connect", "--plain", "web"},
			ssh: ask + " -- deploy@10.0.0.5",
			out: "Connecting to web (deploy@10.0.0.5:22)...\n"},
		{name: "forward", args: []string{"connect", "-F", "all", "--plain", "web"},
			ssh: ask + " -L 5432:localhost:5432 -- deploy@10.0.0.5",
			out: "Connecting to web (deploy@10.0.0.5:22)...\n"},
		{name: "jump", args: []string{"connect", "inner"},
			ssh: ask + " -J ops@gw:2222 -- app@10.0.0.6",
			out: "Connecting to inner (app@10.0.0.6:22) via ops@gw:2222...\n"},
		{name: "mosh", args: []string{"connect", "--mosh", "--plain", "web"},
			mosh: "--ssh=ssh " + ask + " -- deploy@10.0.0.5",
			out:  "Connecting to web (deploy@10.0.0.5:22) with mosh...\n"},
		{name: "mosh session", args: []string{"connect", "--mosh", "web"},
			mosh: "--ssh=ssh " + ask + " -- deploy@10.0.0.5 sh -c " + tmux,
			out:  "Connecting to web (deploy@10.0.0.5:22) with mosh...\n"},
		{name: "mosh forward", args: []string{"connect", "--mosh", "--plain", "-F", "db", "web"},
			ssh:    ask + " -L 5432:localhost:5432 -- deploy@10.0.0.5",
			out:    "Connecting to web (deploy@10.0.0.5:22)...\n",
			errOut: "sshr: mosh cannot forward ports, using ssh\n"},
		{name: "mosh jump", args: []string{"connect", "--mosh", "inner"},
			ssh:    ask + " -J ops@gw:2222 -- app@10.0.0.6",
			out:    "Connecting to inner (app@10.0.0.6:22) via ops@gw:2222...\n",
			errOut: "sshr: mosh does not work through jump hosts, using ssh\n"},
		{name: "unsaved", args: []string{"connect", "root@10.0.0.9:2200"},
			ssh:    "-p 2200 -- root@10.0.0.9",
			out:    "Connecting to 10.0.0.9 (root@10.0.0.9:2200)...\n",
			errOut: "sshr: root@10.0.0.9:2200 is not saved, connecting once\n"},
		{name: "tunnel", args: []string{"tunnel", "web"},
			ssh: ask + " -N -o ExitOnForwardFailure=yes -L 5432:localhost:5432 -- deploy@10.0.0.5",
			out: "  db -L 5432:localhost:5432\nTunnel to web is open, Ctrl+C to close\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, errOut, code := sshrIn(t, home, c.args...)
			if code != c.code {
				t.Errorf("exit %d, want %d (%s)", code, c.code, errOut)
			}
			if got := argsOf(t, tools, "ssh"); got != c.ssh {
				t.Errorf("ssh\n got %q\nwant %q", got, c.ssh)
			}
			if got := argsOf(t, tools, "mosh"); got != c.mosh {
				t.Errorf("mosh\n got %q\nwant %q", got, c.mosh)
			}
			if out != c.out || errOut != c.errOut {
				t.Errorf("printed\n%q %q\nwant\n%q %q", out, errOut, c.out, c.errOut)
			}
		})
	}
}

// a mosh that fails at once falls back to ssh, the exit code of ssh is the
// exit code of sshr
func TestConnectFallbackAndExitCode(t *testing.T) {
	tools := fakeTools(t)
	home := t.TempDir()
	mustRun(t, home, "add", "10.0.0.5", "-u", "deploy", "-n", "web", "--ask-password")
	os.WriteFile(filepath.Join(tools, "mosh.code"), []byte("1"), 0o600)
	os.WriteFile(filepath.Join(tools, "ssh.code"), []byte("7"), 0o600)
	out, errOut, code := sshrIn(t, home, "connect", "--mosh", "web")
	if code != 7 {
		t.Errorf("exit %d, want the 7 of ssh", code)
	}
	if argsOf(t, tools, "mosh") == "" || argsOf(t, tools, "ssh") == "" {
		t.Error("mosh was not tried first or ssh did not follow")
	}
	if !strings.Contains(errOut, "sshr: mosh did not start, falling back to ssh\n") ||
		out != "Connecting to web (deploy@10.0.0.5:22) with mosh...\nConnecting to web (deploy@10.0.0.5:22)...\n" {
		t.Errorf("printed %q %q", out, errOut)
	}
}

// with no mosh installed connect says so and uses ssh, with no ssh it
// stops with a message
func TestConnectMissingTools(t *testing.T) {
	tools := fakeTools(t)
	home := t.TempDir()
	mustRun(t, home, "add", "10.0.0.5", "-u", "deploy", "-n", "web", "--ask-password")
	os.Remove(filepath.Join(tools, "mosh"))
	t.Setenv("PATH", tools)
	out, errOut, code := sshrIn(t, home, "connect", "--mosh", "web")
	if code != 0 || errOut != "sshr: mosh is not installed, using ssh\n" || out != "Connecting to web (deploy@10.0.0.5:22)...\n" || argsOf(t, tools, "ssh") == "" {
		t.Errorf("no mosh: %d %q %q", code, out, errOut)
	}
	os.Remove(filepath.Join(tools, "ssh"))
	out, errOut, code = sshrIn(t, home, "connect", "web")
	if code != 1 || errOut != "sshr: ssh not found in PATH\n" || out != "" {
		t.Errorf("no ssh: %d %q %q", code, out, errOut)
	}
}

// a host down directly goes through its gateway and says why
func TestConnectThroughGateway(t *testing.T) {
	tools := fakeTools(t)
	home := t.TempDir()
	mustRun(t, home, "add", "127.0.0.1", "-p", "1", "-u", "app", "-n", "db", "--ask-password", "--gateway", "ops@gw")
	out, errOut, code := sshrIn(t, home, "connect", "db")
	want := "-o PreferredAuthentications=keyboard-interactive,password -o PubkeyAuthentication=no -p 1 -J ops@gw -- app@127.0.0.1"
	if got := argsOf(t, tools, "ssh"); code != 0 || got != want || out != "Connecting to db (app@127.0.0.1:1) via ops@gw (no answer directly)...\n" || errOut != "" {
		t.Errorf("%d %q %q\nssh %q", code, out, errOut, got)
	}
}

// the secrets of a host are fetched after "Connecting to", a password
// manager prompt or an error that comes from them belongs to the connect
func TestConnectFetchesSecretsAfterTheLine(t *testing.T) {
	fakeTools(t)
	home := t.TempDir()
	dir := filepath.Join(home, ".sshr", "vault", "hosts")
	os.MkdirAll(dir, 0o700)
	id := "0123456789abcdef0123456789abcdef"
	host := `{"id":"` + id + `","name":"k","host":"10.0.0.5","port":22,"user":"u","key_mode":"vault","created_at":"2026-10-23T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(dir, id+".json"), []byte(host), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := sshrIn(t, home, "connect", "k")
	if code != 1 || out != "Connecting to k (u@10.0.0.5:22)...\n" || !strings.Contains(errOut, "has no saved key") {
		t.Errorf("%d %q %q", code, out, errOut)
	}
}
