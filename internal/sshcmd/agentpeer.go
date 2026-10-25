package sshcmd

import (
	"fmt"
	"net"
	"os"
)

// maxPeerDepth bounds the walk up the parents of an agent peer, ssh under
// mosh under sshr is three steps, a loop in a broken process table ends
const maxPeerDepth = 32

// checkAgentPeer lets in the process at the other end of an agent
// connection when it is sshr itself or one it started, ssh, the ssh of a
// jump host or mosh, any program of the same user outside sshr is
// refused, it could log in elsewhere with the key while a session runs,
// a program sshr started (a local command of a host, an extension in
// sshr serve) passes too, the check knows the tree and not the one ssh,
// the error says why, on Windows the peer of the pipe and its parents are
// read the same way, where the system gives no peer process (the BSDs)
// every peer of the user is let in
func checkAgentPeer(c net.Conn) error {
	pid, ok, err := peerPID(c)
	if err != nil {
		return fmt.Errorf("the process on the other end is unknown: %v", err)
	}
	if !ok {
		return nil
	}
	if !descendantOf(pid, os.Getpid(), parentPID) {
		return fmt.Errorf("process %d was not started by sshr, or its parents cannot be read (/proc with hidepid, another PID namespace)", pid)
	}
	return nil
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
