//go:build !windows

package sshcmd

import (
	"net"
	"os"
	"path/filepath"
)

// listenAgent opens the agent socket in the 0700 ControlDir, or in a fresh
// 0700 temp directory when there is none short enough, cleanup removes it
func listenAgent(name string) (ln net.Listener, sock string, cleanup func(), err error) {
	dir, err := ControlDir()
	cleanDir := func() {}
	if err != nil {
		if dir, err = os.MkdirTemp("", "sshr-"); err != nil {
			return nil, "", nil, err
		}
		cleanDir = func() { os.Remove(dir) }
	}
	sock = filepath.Join(dir, "ag-"+name)
	if ln, err = net.Listen("unix", sock); err != nil {
		cleanDir()
		return nil, "", nil, err
	}
	return ln, sock, func() {
		ln.Close()
		os.Remove(sock)
		cleanDir()
	}, nil
}

// dialAgent connects to an agent socket
func dialAgent(sock string) (net.Conn, error) {
	return net.Dial("unix", sock)
}
