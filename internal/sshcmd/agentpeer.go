package sshcmd

import (
	"net"
	"os"
)

// maxPeerDepth bounds the walk up the parents of an agent peer, ssh under
// mosh under sshr is three steps, a loop in a broken process table ends
const maxPeerDepth = 32

// fromOwnChild tells whether the process at the other end of an agent
// connection is sshr itself or one it started, ssh, the ssh of a jump
// host or mosh, any other program of the same user is refused, it could
// log in elsewhere with the key while a session runs, where the system
// gives no peer process (Windows pipes) every peer of the user is let in
func fromOwnChild(c net.Conn) bool {
	pid, ok, err := peerPID(c)
	if err != nil {
		return false
	}
	if !ok {
		return true
	}
	return descendantOf(pid, os.Getpid(), parentPID)
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
