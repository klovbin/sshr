//go:build linux

package sshcmd

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// a child of this process passes the agent check, a process whose parent
// left (reparented to init or a subreaper above this process) does not,
// the refusal says why (#349)
func TestFromOwnChild(t *testing.T) {
	if sock := os.Getenv("SSHR_AGENTPEER_DIAL"); sock != "" {
		if c, err := net.Dial("unix", sock); err == nil {
			time.Sleep(2 * time.Second)
			c.Close()
		}
		return
	}
	// as PID 1 (a container started with the test binary) the orphan is
	// reparented to this process and would pass (#351)
	if os.Getpid() == 1 {
		t.Skip("the test binary is PID 1, an orphan would be its child")
	}
	sock := filepath.Join(t.TempDir(), "ag")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accept := func() net.Conn {
		t.Helper()
		ln.(*net.UnixListener).SetDeadline(time.Now().Add(10 * time.Second))
		c, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	env := append(os.Environ(), "SSHR_AGENTPEER_DIAL="+sock)
	child := exec.Command(os.Args[0], "-test.run=^TestFromOwnChild$", "-test.count=1")
	child.Env = env
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Wait()
	c := accept()
	if err := checkAgentPeer(c); err != nil {
		t.Errorf("a child of sshr was refused: %v", err)
	}
	c.Close()
	// the shell starts the dialer in the background and leaves, the dialer
	// is an orphan by the time it connects
	orphan := exec.Command("sh", "-c", `(sleep 0.5; exec "$0" -test.run='^TestFromOwnChild$' -test.count=1) >/dev/null 2>&1 &`, os.Args[0])
	orphan.Env = env
	if err := orphan.Run(); err != nil {
		t.Fatal(err)
	}
	c = accept()
	if err := checkAgentPeer(c); err == nil {
		t.Error("a process that is not under sshr got the agent")
	} else if !strings.Contains(err.Error(), "was not started by sshr") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	c.Close()
}
