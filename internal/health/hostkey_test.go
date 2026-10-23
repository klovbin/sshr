package health

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"sshr.dev/internal/hosts"
)

// sshServer answers the key exchange with a fresh ed25519 key and refuses
// every login, it returns the port and the key
func sshServer(t *testing.T) (int, ssh.PublicKey) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: false, PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
		return nil, os.ErrPermission
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				ssh.NewServerConn(c, cfg)
				c.Close()
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, signer.PublicKey()
}

func TestCheckHostKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	port, key := sshServer(t)
	h := &hosts.Host{Host: "127.0.0.1", User: "u", Port: port}
	if k := CheckHostKey(h); k.State != KeyUnknown || k.Fingerprint != ssh.FingerprintSHA256(key) {
		t.Fatalf("no known_hosts: %+v", k)
	}
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	addr := knownhosts.Normalize(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	known := filepath.Join(home, ".ssh", "known_hosts")
	os.WriteFile(known, []byte(knownhosts.Line([]string{addr}, key)+"\n"), 0o600)
	if k := CheckHostKey(h); k.State != KeyKnown {
		t.Fatalf("known key: %+v", k)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(other)
	os.WriteFile(known, []byte(knownhosts.Line([]string{addr}, otherSigner.PublicKey())+"\n"), 0o600)
	if k := CheckHostKey(h); k.State != KeyChanged {
		t.Fatalf("changed key: %+v", k)
	}
	if k := CheckHostKey(&hosts.Host{Host: "10.0.0.1", User: "u", Jump: "b"}); k.Fingerprint != "" || k.Err == "" {
		t.Errorf("a host behind a jump host was checked: %+v", k)
	}
}
