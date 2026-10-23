package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshr.dev/internal/api"
)

func TestAPIListenerKeepsAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	os.WriteFile(path, []byte("keep"), 0o600)
	if _, _, err := apiListener("unix:"+path, &api.Options{}); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("listen on a regular file = %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "keep" {
		t.Fatal("the file was removed")
	}
}

func TestAPIListenerReplacesAStaleSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "sshr")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "api.sock")
	old, err := net.Listen("unix", path)
	if err != nil {
		t.Skip("no unix sockets here:", err)
	}
	// closing without unlinking leaves the socket file as a crash would
	old.(*net.UnixListener).SetUnlinkOnClose(false)
	old.Close()
	ln, _, err := apiListener("unix:"+path, &api.Options{})
	if err != nil {
		t.Fatalf("listen over a stale socket = %v", err)
	}
	ln.Close()
}
