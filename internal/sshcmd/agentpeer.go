package sshcmd

import (
	"fmt"
	"net"
	"os"
	"os/exec"
)

// maxPeerDepth bounds the walk up the parents of an agent peer, ssh under
// mosh under sshr is three steps, a loop in a broken process table ends
const maxPeerDepth = 32

// checkAgentPeer lets in the process at the other end of an agent
// connection when it is root or one root started, root is the ssh of the
// login once it runs (with mosh or the ssh of a jump host under it), so
// another login or an extension of a long running sshr serve does not get
// the key, before that, or when sshr became ssh itself, root is sshr, any
// program of the same user outside the tree is refused, it could log in
// elsewhere with the key while a session runs, the error says why, on
// Windows the peer of the pipe and its parents are read the same way,
// where the system gives no peer process (the BSDs) every peer of the user
// is let in
func checkAgentPeer(c net.Conn, root int) error {
	pid, ok, err := peerPID(c)
	if err != nil {
		return fmt.Errorf("the process on the other end is unknown: %v", err)
	}
	if !ok {
		return nil
	}
	if !descendantOf(pid, root, parentPID) {
		return fmt.Errorf("process %d is not the ssh of this login or under it, or its parents cannot be read (/proc with hidepid, another PID namespace)", pid)
	}
	return nil
}

// agentRoot is the process an agent of cmd answers, the ssh of the login
// once it started, sshr itself before
func agentRoot(cmd *exec.Cmd) int {
	if cmd != nil && cmd.Process != nil {
		return cmd.Process.Pid
	}
	return os.Getpid()
}

// descendantOf tells whether pid is root or under it, parent gives the
// parent of a process, 0 or an error ends the walk
func descendantOf(pid, root int, parent func(int) (int, error)) bool {
	for i := 0; i < maxPeerDepth && pid > 1; i++ {
		if pid == root {
			return true
		}
		next, err := parent(pid)
		if err != nil || next == pid {
			return false
		}
		pid = next
	}
	return pid == root
}
