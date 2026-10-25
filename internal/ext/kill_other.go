//go:build !windows

package ext

import "os/exec"

// killTree stops an extension, its own process group is not used: the
// importer may ask the user on the terminal and a process outside the
// foreground group would be stopped by the first read, a child left
// behind dies on its next write to the closed output
func killTree(cmd *exec.Cmd) {
	cmd.Process.Kill()
}
