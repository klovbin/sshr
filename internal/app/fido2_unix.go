//go:build !windows && !linux

package app

import (
	"os/exec"
	"syscall"
)

// detachTerminal starts cmd in a session of its own, without a controlling
// terminal it cannot ask for a PIN in the terminal sshr was started from
// or be stopped for reading it in the background
func detachTerminal(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
