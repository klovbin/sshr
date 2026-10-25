package app

import (
	"os/exec"
	"syscall"
)

// shellCommand runs command through cmd.exe, the command line is passed as
// it is: Go would escape quotes in an argument as \", which cmd.exe does
// not read, /S takes off only the outer quotes added here
func shellCommand(command string) *exec.Cmd {
	cmd := exec.Command("cmd")
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: shellCmdLine(command)}
	return cmd
}

func shellCmdLine(command string) string { return `cmd /S /C "` + command + `"` }
