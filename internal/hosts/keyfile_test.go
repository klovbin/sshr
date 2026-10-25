package hosts

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// skHandle builds the file ssh-keygen -t ed25519-sk writes, an OpenSSH
// private key whose private part is a handle on the token, no token is
// needed to build it
func skHandle(t *testing.T) []byte {
	t.Helper()
	str := func(b []byte) []byte {
		out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
		return append(out, b...)
	}
	typ := []byte("sk-ssh-ed25519@openssh.com")
	key := make([]byte, ed25519.PublicKeySize)
	rand.Read(key)
	pub := append(append(str(typ), str(key)...), str([]byte("ssh:"))...)
	priv := []byte{1, 2, 3, 4, 1, 2, 3, 4}
	priv = append(priv, str(typ)...)
	priv = append(priv, str(key)...)
	priv = append(priv, str([]byte("ssh:"))...)
	priv = append(priv, 0x01) // flags: user presence
	priv = append(priv, str([]byte("handle-of-the-token"))...)
	priv = append(priv, str(nil)...)
	priv = append(priv, str([]byte("u@h"))...)
	for i := byte(1); len(priv)%8 != 0; i++ {
		priv = append(priv, i)
	}
	body := []byte("openssh-key-v1\x00")
	body = append(body, str([]byte("none"))...)
	body = append(body, str([]byte("none"))...)
	body = append(body, str(nil)...)
	body = binary.BigEndian.AppendUint32(body, 1)
	body = append(body, str(pub)...)
	body = append(body, str(priv)...)
	return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: body})
}

func TestHardwareKeyType(t *testing.T) {
	handle := skHandle(t)
	if got := HardwareKeyType(handle); got != "sk-ssh-ed25519@openssh.com" {
		t.Errorf("sk handle: %q", got)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "c")
	if got := HardwareKeyType(pem.EncodeToMemory(block)); got != "" {
		t.Errorf("a software key is taken as hardware: %q", got)
	}
	for _, bad := range [][]byte{nil, []byte("junk"), handle[:60], pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("openssh-key-v1\x00\xff\xff\xff\xff")})} {
		if got := HardwareKeyType(bad); got != "" {
			t.Errorf("%q gave %q", bad, got)
		}
	}
	path := filepath.Join(t.TempDir(), "id_sk")
	os.WriteFile(path, handle, 0o600)
	if HardwareKeyFile(path) == "" || HardwareKeyFile(path+".missing") != "" {
		t.Error("HardwareKeyFile")
	}
	// the handle is a key file sshr accepts as it is
	if err := CheckPrivateKey(path); err != nil {
		t.Errorf("CheckPrivateKey of a handle: %v", err)
	}
}

// a handle pasted into vault mode is refused with a reason, the agent of
// sshr cannot sign with a key that lives on a token
func TestVaultRefusesAHardwareKey(t *testing.T) {
	h := Host{Name: "web", Host: "h", User: "u", KeyMode: KeyVault, KeyData: skHandle(t)}
	if err := prepareVaultKey(&h); !errors.Is(err, ErrHardwareKeyInVault) {
		t.Fatalf("prepareVaultKey = %v", err)
	}
}
