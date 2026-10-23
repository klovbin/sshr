package hosts

import (
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"sshr.dev/internal/fileio"
)

// ErrKeyPassphrase means the pasted key is protected with a passphrase and
// none was given
var ErrKeyPassphrase = errors.New("key_passphrase")

// prepareVaultKey checks a pasted private key and turns it into the form
// that is sealed, a passphrase-protected key is opened with h.KeyPassphrase
// and kept without it, the vault encryption replaces the passphrase, the
// public key is kept in the clear for -i and for showing which key it is
func prepareVaultKey(h *Host) error {
	data := []byte(strings.TrimSpace(string(h.KeyData)) + "\n")
	raw, err := ssh.ParseRawPrivateKey(data)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if h.KeyPassphrase == "" {
			return ErrKeyPassphrase
		}
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(data, []byte(h.KeyPassphrase))
	}
	if err != nil {
		return fmt.Errorf("not a private key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return err
	}
	block, err := ssh.MarshalPrivateKey(raw, h.Name)
	if err != nil {
		return err
	}
	h.KeyData = pem.EncodeToMemory(block)
	h.KeyPassphrase = ""
	h.KeyPub = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return nil
}

// PubPath is where the public half of a vault key is written for ssh -i,
// with IdentitiesOnly it makes ssh offer only this key from the agent
func (s *Store) PubPath(h *Host) string {
	return filepath.Join(s.Dir, h.ID+".pub")
}

// WritePub writes the public half of a vault key next to the host file,
// it is not secret
func (s *Store) WritePub(h *Host) error {
	path := s.PubPath(h)
	if !h.ServedByAgent() && !(h.KeyMode == KeyAgent && h.KeyPub != "") {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return fileio.WriteFile(path, []byte(h.KeyPub+"\n"), 0o600)
}
