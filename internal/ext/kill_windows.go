//go:build windows

package ext

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// killTree stops an extension with every process it started: an extension
// of Windows is often a .cmd that starts PowerShell, killing cmd.exe alone
// leaves that child running, taskkill /T walks the tree by parent while
// the parent still lives, so it runs before the plain kill
func killTree(cmd *exec.Cmd) {
	taskkill := "taskkill.exe"
	if root := os.Getenv("SystemRoot"); root != "" {
		taskkill = filepath.Join(root, "System32", "taskkill.exe")
	}
	// a taskkill that hangs must not hold the import, the plain kill below
	// still stops the parent
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	exec.CommandContext(ctx, taskkill, "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
	cmd.Process.Kill()
}
