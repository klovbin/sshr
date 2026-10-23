//go:build unix

package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
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

// the socket names the uid of a client, this process is the same user
// (#101)
func TestPeerUIDOverSocket(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("no peer credentials here")
	}
	path := filepath.Join(t.TempDir(), "api.sock")
	ln, err := listenPrivate(path)
	if err != nil {
		t.Skip("no unix sockets here:", err)
	}
	hs := &http.Server{ConnContext: peerContext, Handler: peerGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := r.Context().Value(peerKey{}).(peer)
		if p.err != nil || p.uid != os.Getuid() {
			t.Errorf("peer %+v, want uid %d", p, os.Getuid())
		}
	}))}
	go hs.Serve(ln)
	defer hs.Close()
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", path)
	}}}
	resp, err := c.Get("http://localhost/v1/hosts")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("same user = %d", resp.StatusCode)
	}
}
