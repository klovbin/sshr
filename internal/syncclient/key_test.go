package syncclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testKeyPEM(t *testing.T) []byte {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "t")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}

func TestCleanName(t *testing.T) {
	if got := CleanName("lap\x1b[2Jtop‮\n"); got != "lap[2Jtop" {
		t.Errorf("CleanName = %q", got)
	}
	if got := CleanName("ноутбук 2"); got != "ноутбук 2" {
		t.Errorf("CleanName dropped letters: %q", got)
	}
}

func TestShortNeverPanics(t *testing.T) {
	if short("ab", 8) != "ab" || short("abcdefghij", 8) != "abcdefgh" || short("", 6) != "" {
		t.Error("short")
	}
	if n := conflictName("web", "x"); !strings.Contains(n, "(conflict x ") {
		t.Errorf("conflictName with a short device = %q", n)
	}
}
