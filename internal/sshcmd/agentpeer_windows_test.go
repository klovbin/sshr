//go:build windows

package sshcmd

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
)

// a child of this process passes the agent check on a named pipe, the
// pipe gives the process on its other end
func TestFromOwnChildOnWindows(t *testing.T) {
	if sock := os.Getenv("SSHR_AGENTPEER_PIPE"); sock != "" {
		if c, err := winio.DialPipe(sock, nil); err == nil {
			time.Sleep(2 * time.Second)
			c.Close()
		}
		return
	}
	ln, sock, cleanup, err := listenAgent("peertest")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	child := exec.Command(os.Args[0], "-test.run=^TestFromOwnChildOnWindows$", "-test.count=1")
	child.Env = append(os.Environ(), "SSHR_AGENTPEER_PIPE="+sock)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Wait()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	pid, ok, err := peerPID(c)
	if err != nil || !ok || pid != child.Process.Pid {
		t.Fatalf("peer %d %v %v, the child is %d", pid, ok, err, child.Process.Pid)
	}
	if err := checkAgentPeer(c, os.Getpid()); err != nil {
		t.Errorf("a child of sshr was refused: %v", err)
	}
	if p, err := parentPID(os.Getpid()); err != nil || p == 0 {
		t.Errorf("the parent of the test %d %v", p, err)
	}
}
