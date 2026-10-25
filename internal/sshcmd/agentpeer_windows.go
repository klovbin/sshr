//go:build windows

package sshcmd

import (
	"errors"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// peerPID is the process on the other end of a named pipe of the agent,
// from GetNamedPipeClientProcessId on the pipe handle go-winio gives
func peerPID(c net.Conn) (int, bool, error) {
	f, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return 0, false, errors.New("not a named pipe")
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(f.Fd()), &pid); err != nil {
		return 0, false, err
	}
	return int(pid), true, nil
}

// parentPID is the parent Windows recorded for pid, only when that number
// still opens a process that started before pid, Windows hands the number
// of a process that ended to a new one, a process whose parent left would
// otherwise be taken for a child of whatever got that number later, sshr
// included, a process can name another parent for a child it starts
// (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS), so this keeps out tools that only
// found the pipe, not code that works against the user
func parentPID(pid int) (int, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if int(e.ProcessID) != pid {
			continue
		}
		parent := int(e.ParentProcessID)
		child, cerr := startTime(pid)
		born, perr := startTime(parent)
		if cerr != nil || perr != nil || born > child {
			return 0, nil
		}
		return parent, nil
	}
	return 0, errors.New("the process is gone")
}

// startTime is when pid started, in 100 ns steps since 1601
func startTime(pid int) (int64, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return 0, err
	}
	return created.Nanoseconds() / 100, nil
}
