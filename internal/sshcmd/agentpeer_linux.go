//go:build linux

package sshcmd

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// peerPID is the process at the other end of a unix socket, from
// SO_PEERCRED
func peerPID(c net.Conn) (int, bool, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, false, errors.New("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false, err
	}
	var cred *unix.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, false, err
	}
	if serr != nil {
		return 0, false, serr
	}
	return int(cred.Pid), true, nil
}

// parentPID reads the parent of pid from /proc/pid/stat, the field after
// the name in parentheses, which may hold spaces and parentheses itself
func parentPID(pid int) (int, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, fmt.Errorf("/proc/%d/stat has no name", pid)
	}
	f := bytes.Fields(b[i+1:])
	if len(f) < 2 {
		return 0, fmt.Errorf("/proc/%d/stat is short", pid)
	}
	return strconv.Atoi(string(f[1]))
}
