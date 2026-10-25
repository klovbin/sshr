package sshcmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// certHome gives the test a home of its own and a vault in memory
func certHome(t *testing.T) {
	t.Helper()
	useMockKeychain(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
}

// a software authority is made once, read back and signs a user
// certificate a server checker takes for the principal and not for
// another, an authority there stays without --replace
func TestSoftwareCASigns(t *testing.T) {
	certHome(t)
	if _, err := LoadCertCA(); !errors.Is(err, ErrNoCA) {
		t.Fatalf("no authority yet: %v", err)
	}
	made, err := InitSoftwareCA(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InitSoftwareCA(false); err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Errorf("a second authority without --replace: %v", err)
	}
	ca, err := LoadCertCA()
	if err != nil || ca.Pub != made.Pub {
		t.Fatalf("read back: %+v %v", ca, err)
	}
	caPub, err := ca.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userPub, _ := ssh.NewPublicKey(pub)
	now := time.Now()
	cert, err := ca.SignUserCert(userPub, "sshr web", []string{"deploy"}, 10, now)
	if err != nil {
		t.Fatal(err)
	}
	checker := ssh.CertChecker{IsUserAuthority: func(k ssh.PublicKey) bool {
		return string(k.Marshal()) == string(caPub.Marshal())
	}}
	if err := checker.CheckCert("deploy", cert); err != nil {
		t.Errorf("the server refuses the certificate: %v", err)
	}
	if err := checker.CheckCert("root", cert); err == nil {
		t.Error("the certificate holds for another principal")
	}
	if _, ok := cert.Permissions.Extensions["permit-agent-forwarding"]; ok {
		t.Error("the certificate allows agent forwarding")
	}
	if got := time.Unix(int64(cert.ValidBefore), 0).Sub(now); got > 11*time.Minute || got < 9*time.Minute {
		t.Errorf("the certificate holds for %v", got)
	}
	if _, err := ca.SignUserCert(userPub, "x", nil, 10, now); err == nil {
		t.Error("a certificate without a principal")
	}
}

// an authority whose file shows another key than the sealed one signs
// nothing
func TestSoftwareCAKeyMustMatch(t *testing.T) {
	certHome(t)
	ca, err := InitSoftwareCA(false)
	if err != nil {
		t.Fatal(err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _ := ssh.NewPublicKey(other)
	ca.Pub = authorizedLine(otherPub, "sshr-ca")
	if _, err := ca.SignUserCert(otherPub, "x", []string{"u"}, 10, time.Now()); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("a changed authority file: %v", err)
	}
}
