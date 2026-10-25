//go:build !windows

package sshcmd

import "os"

// openTerminal opens the controlling terminal, it fails when there is none,
// as in the GUI
func openTerminal() (in, out *os.File, err error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	return f, f, err
}
