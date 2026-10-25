package hosts

import (
	"bytes"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ExpandHome turns ~/… into an absolute path under the user home.
func ExpandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// CheckPrivateKey accepts a small file with a "PRIVATE KEY" header (OpenSSH
// and PEM), so a public key or a wrong path fails at save, not later at connect.
func CheckPrivateKey(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("key file not found: %s", path)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 16384 {
		return fmt.Errorf("not a private key file: %s", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !strings.Contains(string(b), "PRIVATE KEY") {
		if strings.HasSuffix(path, ".pub") {
			return fmt.Errorf("%s is a public key; pass the file without .pub", path)
		}
		return fmt.Errorf("not a private key file: %s", path)
	}
	return nil
}

// HardwareKeyType is the type of an OpenSSH private key file whose key
// lives on a FIDO token (sk-ssh-ed25519@openssh.com,
// sk-ecdsa-sha2-nistp256@openssh.com), empty for any other key, the file
// of such a key is only a handle, signing needs the token, the type is
// read from the public part of the file, which is not encrypted even when
// the handle has a passphrase
func HardwareKeyType(data []byte) string {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" {
		return ""
	}
	rest, ok := bytes.CutPrefix(block.Bytes, []byte("openssh-key-v1\x00"))
	if !ok {
		return ""
	}
	// cipher, kdf and kdf options, then the number of keys
	for i := 0; i < 3; i++ {
		if _, rest, ok = sshString(rest); !ok {
			return ""
		}
	}
	if len(rest) < 4 || binary.BigEndian.Uint32(rest) != 1 {
		return ""
	}
	pub, _, ok := sshString(rest[4:])
	if !ok {
		return ""
	}
	typ, _, ok := sshString(pub)
	if !ok || !strings.HasPrefix(string(typ), "sk-") {
		return ""
	}
	return string(typ)
}

// HardwareKeyFile is HardwareKeyType of the key file at path, empty when
// it does not read
func HardwareKeyFile(path string) string {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16384 {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return HardwareKeyType(b)
}

// sshString reads one length-prefixed string of the SSH wire format
func sshString(b []byte) (s, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, b, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, b, false
	}
	return b[4 : 4+n], b[4+n:], true
}
