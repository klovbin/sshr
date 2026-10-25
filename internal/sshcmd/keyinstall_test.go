package sshcmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestKeygenArgsNeverOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	if _, err := KeygenArgs(path, "c", true); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path+".pub", []byte("x"), 0o600)
	if _, err := KeygenArgs(path, "c", true); err == nil {
		t.Fatal("an existing .pub would be overwritten")
	}
}

// a key with a passphrase gets 64 rounds of the passphrase KDF, a key
// without one gets an empty passphrase and no rounds
func TestKeygenArgsRounds(t *testing.T) {
	dir := t.TempDir()
	args, err := KeygenArgs(filepath.Join(dir, "a"), "c", false)
	if err != nil || !strings.Contains(strings.Join(args, " "), "-a 64") || strings.Contains(strings.Join(args, " "), "-N") {
		t.Errorf("with a passphrase: %v %v", args, err)
	}
	args, err = KeygenArgs(filepath.Join(dir, "b"), "c", true)
	if err != nil || strings.Contains(strings.Join(args, " "), "-a") || !strings.Contains(strings.Join(args, " "), "-N ") {
		t.Errorf("without a passphrase: %v %v", args, err)
	}
}

func TestReadPublicKey(t *testing.T) {
	dir := t.TempDir()
	_, pub := testKey(t, "")
	good := filepath.Join(dir, "k.pub")
	os.WriteFile(good, []byte(pub+"\n"), 0o600)
	if line, err := ReadPublicKey(good); err != nil || line != pub {
		t.Fatalf("ReadPublicKey = %q %v", line, err)
	}
	priv, _ := testKey(t, "")
	bad := filepath.Join(dir, "k")
	os.WriteFile(bad, priv, 0o600)
	if _, err := ReadPublicKey(bad); err == nil {
		t.Error("a private key was taken as public")
	}
	two := filepath.Join(dir, "two.pub")
	os.WriteFile(two, []byte(pub+"\n"+pub+"\n"), 0o600)
	if _, err := ReadPublicKey(two); err == nil {
		t.Error("two keys were taken as one")
	}
}

func TestInstallKeyScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs sh")
	}
	home := t.TempDir()
	_, pub := testKey(t, "")
	run := func() string {
		cmd := exec.Command("sh", "-c", installKeyScript)
		cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
		cmd.Stdin = strings.NewReader(pub + "\n")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if got := run(); got != "added" {
		t.Fatalf("first run = %q", got)
	}
	if got := run(); got != "already there" {
		t.Fatalf("second run = %q", got)
	}
	b, _ := os.ReadFile(filepath.Join(home, ".ssh", "authorized_keys"))
	if strings.Count(string(b), pub) != 1 {
		t.Fatalf("authorized_keys = %q", b)
	}
	if fi, _ := os.Stat(filepath.Join(home, ".ssh", "authorized_keys")); fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("authorized_keys mode %v", fi.Mode())
	}
}

// a key on a FIDO token: the type, resident and verify-required reach
// ssh-keygen, the path is never overwritten
func TestSKKeygenArgs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sk")
	args, err := SKKeygenArgs(path, "c", "ed25519-sk", true, true, false)
	if err != nil {
		t.Fatal(err)
	}
	want := "-t ed25519-sk -f " + path + " -C c -O resident -O verify-required"
	if got := strings.Join(args, " "); got != want {
		t.Errorf("args %q, want %q", got, want)
	}
	if args, _ := SKKeygenArgs(path, "c", "ecdsa-sk", false, false, false); strings.Contains(strings.Join(args, " "), "-O") {
		t.Errorf("options without asking: %q", args)
	}
	os.WriteFile(path, []byte("x"), 0o600)
	if _, err := SKKeygenArgs(path, "c", "ed25519-sk", false, false, false); err == nil {
		t.Error("an existing handle would be overwritten")
	}
	if !SKUnsupported("Key enrollment failed: requested feature not supported\n") || SKUnsupported("Key enrollment failed: invalid PIN") {
		t.Error("SKUnsupported")
	}
}
