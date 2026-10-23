//go:build unix

package main

import (
	"net"
	"os"
	"syscall"
)

// listenPrivate opens a unix socket only this user can connect to, created
// under umask 077 so no other user can reach it before the chmod
func listenPrivate(path string) (net.Listener, error) {
	old := syscall.Umask(0o077)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}
