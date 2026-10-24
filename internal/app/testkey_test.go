package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testKey makes an ed25519 key in OpenSSH form, with a passphrase when one
// is given, and its public line, the password manager tests hand it out
func testKey(t *testing.T, passphrase string) (pemData []byte, pub string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "t")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "t", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	return pem.EncodeToMemory(block), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}
