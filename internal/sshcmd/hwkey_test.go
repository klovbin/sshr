package sshcmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"sshr.dev/internal/settings"
)

// skHandleFile writes the file ssh-keygen -t ed25519-sk makes, no token is
// needed for the public part sshr reads
func skHandleFile(t *testing.T, dir string) string {
	t.Helper()
	str := func(b []byte) []byte { return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...) }
	typ, key := []byte("sk-ssh-ed25519@openssh.com"), make([]byte, ed25519.PublicKeySize)
	pub := append(append(str(typ), str(key)...), str([]byte("ssh:"))...)
	priv := append([]byte{1, 2, 3, 4, 1, 2, 3, 4}, pub...)
	priv = append(append(priv, 1), str([]byte("handle"))...)
	priv = append(append(priv, str(nil)...), str([]byte("c"))...)
	for i := byte(1); len(priv)%8 != 0; i++ {
		priv = append(priv, i)
	}
	body := append([]byte("openssh-key-v1\x00"), str([]byte("none"))...)
	body = append(append(body, str([]byte("none"))...), str(nil)...)
	body = append(binary.BigEndian.AppendUint32(body, 1), str(pub)...)
	body = append(body, str(priv)...)
	path := filepath.Join(dir, "id_sk")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: body}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// a host under the requirement connects only with a key on a token
func TestCheckHardwareKey(t *testing.T) {
	dir := t.TempDir()
	sk := skHandleFile(t, dir)
	plain := filepath.Join(dir, "id_ed25519")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "c")
	os.WriteFile(plain, pem.EncodeToMemory(block), 0o600)
	signer, _ := ssh.NewSignerFromKey(priv)
	softPub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	skPub := "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIHIbECQGRB3NLg97SPN3A8L+r0iy7tQjMlb9OqjlYhH6AAAABHNzaDo="
	for _, c := range []struct {
		name string
		h    Host
		ok   bool
	}{
		{"sk key file", Host{Name: "a", Key: sk}, true},
		{"plain key file", Host{Name: "b", Key: plain}, false},
		{"default keys", Host{Name: "c"}, false},
		{"saved password", Host{Name: "d", Key: sk, PasswordMode: PasswordSaved}, false},
		{"vault key", Host{Name: "e", KeyMode: KeyVault}, false},
		{"1Password key", Host{Name: "f", KeyMode: KeyOnePassword}, false},
		{"agent sk key", Host{Name: "g", KeyMode: KeyAgent, KeyPub: skPub}, true},
		{"agent software key", Host{Name: "h", KeyMode: KeyAgent, KeyPub: softPub}, false},
		{"agent any key", Host{Name: "i", KeyMode: KeyAgent}, false},
	} {
		err := CheckHardwareKey(&c.h)
		if (err == nil) != c.ok || err != nil && !errors.Is(err, ErrHardwareKeyRequired) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// under the requirement ssh gets only sk key types and no password and
// no shared connection, the same host without it keeps reuse
func TestConnectArgsUnderTheRequirement(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SSHR_REUSE", "1")
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Name: "web", Host: "10.0.0.1", User: "u", Key: skHandleFile(t, home)})
	if err != nil {
		t.Fatal(err)
	}
	st, _ := settings.Load()
	st.RequireHardwareKey(h.ID)
	if err := settings.Save(st); err != nil {
		t.Fatal(err)
	}
	args, err := s.ConnectArgs(h)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Join(args, " ")
	for _, want := range []string{"PasswordAuthentication=no", "PubkeyAcceptedKeyTypes=sk-ssh-ed25519@openssh.com", "ControlPath=none"} {
		if !strings.Contains(line, want) {
			t.Errorf("no %s in %s", want, line)
		}
	}
	if strings.Contains(line, "ControlMaster=auto") {
		t.Errorf("a shared connection under the requirement: %s", line)
	}
	other, _ := s.Add(Host{Name: "db", Host: "10.0.0.2", User: "u", PasswordMode: PasswordAsk})
	if _, err := s.ConnectArgs(other); err != nil {
		t.Errorf("a host outside the list was refused: %v", err)
	}
	st.HardwareKey = settings.HardwareKeyAll
	settings.Save(st)
	if _, err := s.ConnectArgs(other); !errors.Is(err, ErrHardwareKeyRequired) {
		t.Errorf("all hosts asked, a password host went through: %v", err)
	}
}

// a settings file that does not parse keeps the requirement when it names
// hardware_key, a mode this build does not know asks it of every host
// (#352)
func TestHardwareKeyRequiredFailsClosed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	path, err := settings.Path()
	if err != nil {
		t.Fatal(err)
	}
	h := &Host{ID: "0123456789abcdef0123456789abcdef", Name: "web"}
	os.WriteFile(path, []byte(`{"hardware_key": "listed", "hardware_key_hosts": [`), 0o600)
	if !hardwareKeyRequired(h) {
		t.Error("a broken file that names the requirement dropped it")
	}
	os.WriteFile(path, []byte(`{"lang": `), 0o600)
	if hardwareKeyRequired(h) {
		t.Error("a broken file without the requirement asked for a hardware key")
	}
	os.WriteFile(path, []byte(`{"hardware_key": "evrything"}`), 0o600)
	if !hardwareKeyRequired(h) {
		t.Error("an unknown mode asked for nothing")
	}
}
