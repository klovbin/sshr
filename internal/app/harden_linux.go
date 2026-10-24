//go:build linux

package app

import "golang.org/x/sys/unix"

// harden makes the process not dumpable, another process of the same
// user can then neither attach with ptrace nor read /proc/pid/mem, and the
// kernel writes no core file of it, the vault key and the opened secrets
// sit in this memory, ssh started from here gets the default back on exec
func harden() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	return noCore()
}
