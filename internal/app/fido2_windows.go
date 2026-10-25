//go:build windows

package app

import "os/exec"

// detachTerminal does nothing on Windows, the token is not asked there yet
func detachTerminal(*exec.Cmd) {}
