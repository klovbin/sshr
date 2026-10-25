//go:build unix

package app

import "golang.org/x/sys/unix"

// noCore sets the soft core file limit to 0, so a crash of sshr leaves no
// copy of its memory on disk, the hard limit stays, the programs sshr
// starts (ssh, the shell of a session) can raise theirs again
func noCore() error {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err != nil {
		return err
	}
	lim.Cur = 0
	return unix.Setrlimit(unix.RLIMIT_CORE, &lim)
}
