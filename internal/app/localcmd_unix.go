//go:build !windows

package app

import "os/exec"

// shellCommand runs command through /bin/sh
func shellCommand(command string) *exec.Cmd { return exec.Command("/bin/sh", "-c", command) }
