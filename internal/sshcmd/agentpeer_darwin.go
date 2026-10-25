//go:build darwin

package sshcmd

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// peerPID is the process at the other end of a unix socket, from
// LOCAL_PEERPID
func peerPID(c net.Conn) (int, bool, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, false, errors.New("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false, err
	}
	var pid int
	var serr error
	if err := raw.Control(func(fd uintptr) {
		pid, serr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); err != nil {
		return 0, false, err
	}
	if serr != nil {
		return 0, false, serr
	}
	return pid, true, nil
}

// parentPID asks the kernel for the parent of pid
func parentPID(pid int) (int, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, err
	}
	return int(kp.Eproc.Ppid), nil
}
