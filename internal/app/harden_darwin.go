//go:build darwin

package app

import "golang.org/x/sys/unix"

// harden refuses debuggers with PT_DENY_ATTACH, a process of the same
// user cannot attach and read the vault key out of this memory, and sets
// no core file, a debugger attached already makes the call end the
// process, SSHR_ALLOW_DEBUG skips harden for that case
func harden() error {
	if err := unix.PtraceDenyAttach(); err != nil {
		return err
	}
	return noCore()
}
