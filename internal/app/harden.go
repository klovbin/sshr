package app

import "os"

// Harden closes the memory of this process to other processes of the same
// user where the system allows it: no ptrace, no /proc/pid/mem on Linux,
// no debugger on macOS, no core files, every sshr process may hold the
// vault key or an opened secret, the front ends call it first thing,
// SSHR_ALLOW_DEBUG=1 skips it to attach a debugger
func Harden() error {
	if os.Getenv("SSHR_ALLOW_DEBUG") == "1" {
		return nil
	}
	return harden()
}
