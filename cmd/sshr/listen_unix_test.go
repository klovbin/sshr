//go:build unix

package main

import (
	"path/filepath"
	"syscall"
	"testing"

	"os"
)

// a socket at a custom path is 0600 even under a umask that opens files to
// everyone (#196)
func TestListenPrivateMode(t *testing.T) {
	old := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(old) })
	path := filepath.Join(t.TempDir(), "api.sock")
	ln, err := listenPrivate(path)
	if err != nil {
		t.Skip("no unix sockets here:", err)
	}
	defer ln.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if m := fi.Mode().Perm(); m != 0o600 {
		t.Errorf("socket mode %o, want 600", m)
	}
}
