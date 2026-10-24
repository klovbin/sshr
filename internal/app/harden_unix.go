//go:build unix

package app

import "golang.org/x/sys/unix"

// noCore sets the core file limit to 0, soft and hard, so a crash leaves
// no copy of the memory on disk, the hard limit makes it stick for the
// process and the programs it starts
func noCore() error {
	return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}
