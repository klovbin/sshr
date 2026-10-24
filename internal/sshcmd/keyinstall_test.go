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
