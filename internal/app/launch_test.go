package app

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// PlanSession decides the route on a copy, the host it is given is not
// written, the app shares its hosts between goroutines
func TestPlanSessionLeavesTheHostAlone(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	h := &Host{Name: "db", Host: "127.0.0.1", Port: closedPort(t), User: "u", PasswordMode: PasswordAsk, Gateway: "ops@gw"}
	p, err := s.PlanSession(h, LaunchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Via != "ops@gw" || h.Via() != "" || h.route != "" {
		t.Errorf("plan via %q, host via %q", p.Via, h.Via())
	}
	if !strings.Contains(strings.Join(p.Args, " "), "-J ops@gw -- u@127.0.0.1") {
		t.Errorf("args %v", p.Args)
	}
}

// the ssh fallback of a mosh plan is built from the same options, the
// gateway is not checked a second time
func TestPlanSessionMoshFallback(t *testing.T) {
	fakeTool(t, "mosh")
	s := &Store{Dir: t.TempDir()}
	h := &Host{Name: "w", Host: "10.0.0.5", Port: 22, User: "u", PasswordMode: PasswordAsk, Session: "tmux"}
	p, err := s.PlanSession(h, LaunchOptions{Mosh: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.Tool != "mosh" || p.Fallback == nil || p.Fallback.Tool != "ssh" || p.Session != "tmux" {
		t.Fatalf("plan %+v", p)
	}
	ssh := strings.Join(p.Fallback.Args, " ")
	if !strings.HasPrefix(p.Args[0], "--ssh=ssh ") || !strings.Contains(ssh, "-t -- u@10.0.0.5") {
		t.Errorf("mosh %v, ssh %v", p.Args, p.Fallback.Args)
	}
	if !MoshStartFailed(1, 0) || MoshStartFailed(0, 0) || MoshStartFailed(1, moshStartup) {
		t.Error("MoshStartFailed")
	}
}

// a batch tunnel refuses a host that asks for its password, never prompts
// and keeps itself alive, in the order the API has always used
func TestPlanSessionBatchTunnel(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	ask := &Host{Name: "a", Host: "10.0.0.5", Port: 22, User: "u", PasswordMode: PasswordAsk}
	if _, err := s.PlanSession(ask, LaunchOptions{Tunnel: true, Batch: true}); !errors.Is(err, ErrAsksPassword) {
		t.Errorf("ask host: %v", err)
	}
	key := &Host{Name: "k", Host: "10.0.0.5", Port: 22, User: "u", Key: "/k", Session: "tmux"}
	f := Forward{Name: "db", Kind: "L", Spec: "5432:localhost:5432"}
	p, err := s.PlanSession(key, LaunchOptions{Tunnel: true, Batch: true, Forwards: []Forward{f}})
	if err != nil {
		t.Fatal(err)
	}
	want := "-i /k -p 22 -o BatchMode=yes -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -L 5432:localhost:5432 -- u@10.0.0.5"
	if got := strings.Join(p.Args, " "); got != want || p.Session != "" {
		t.Errorf("args\n got %s\nwant %s", got, want)
	}
}

// fakeTool puts an executable called name on PATH that does nothing
func fakeTool(t *testing.T, name string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake tool is a shell script")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}
