package app

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// KeyVault is the KeyMode of a host whose private key is stored sealed in
// its host file instead of a key file on disk
const KeyVault = "vault"

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

// KeyFingerprint is the SHA256 fingerprint of a vault key, as ssh-keygen -l
// shows it, empty when the host has none
func (h *Host) KeyFingerprint() string {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(h.KeyPub))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(pub)
}

// pubPath is where the public half of a vault key is written for ssh -i,
// with IdentitiesOnly it makes ssh offer only this key from the agent
func (s *Store) pubPath(h *Host) string {
	return filepath.Join(s.Dir, h.ID+".pub")
}

// vaultKeyArgs are the ssh options for a host with a vault key, the key
// itself comes from the agent AttachAuth starts, the user's own agent and
// key files are not offered, agent forwarding is off so the server never
// reaches the key
func (s *Store) vaultKeyArgs(h *Host) []string {
	if !h.agentKey() {
		return nil
	}
	// the host file may come from a copy without its .pub next to it
	if _, err := os.Stat(s.pubPath(h)); err != nil {
		s.writePub(h)
	}
	return []string{
		"-i", s.pubPath(h),
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=SSH_AUTH_SOCK",
		"-o", "ForwardAgent=no",
	}
}

// authSockOrigEnv keeps the user's SSH_AUTH_SOCK while it points at the
// agent of a vault key, a jump hop restores it
const authSockOrigEnv = "SSHR_AUTH_SOCK_ORIG"

// agentKey tells whether the key of h is served by an agent of sshr, a
// key sealed in sshr or one read from 1Password
func (h *Host) agentKey() bool {
	return h.KeyMode == KeyVault || h.KeyMode == KeyOnePassword || h.KeyMode == KeyBitwarden
}

// loadKey returns the private key of a host that keeps it in sshr or in
// 1Password
func loadKey(h *Host) (any, error) {
	var plain []byte
	switch h.KeyMode {
	case KeyVault:
		if h.KeySealed == "" {
			if h.KeyPub != "" {
				return nil, fmt.Errorf("the key of %s (%s) is stored on another device, keys do not sync, paste it here to use it", h.Name, h.KeyFingerprint())
			}
			return nil, fmt.Errorf("%s has no saved key, save it again", h.Name)
		}
		var err error
		plain, err = unsealFor(h.KeySealed, h.ID, "key", destination(*h))
		if errors.Is(err, ErrSealBroken) {
			return nil, fmt.Errorf("the saved key of %s does not open with the vault key of this machine (keychain reset or the host copied from another machine), save the key again", h.Name)
		}
		if err != nil {
			return nil, err
		}
	case KeyOnePassword:
		var err error
		if plain, err = opReadKey(h.KeyRef); err != nil {
			return nil, err
		}
	case KeyBitwarden:
		var err error
		if plain, _, err = bwKey(h.KeyRef); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%s keeps no key in sshr", h.Name)
	}
	raw, err := ssh.ParseRawPrivateKey(plain)
	if err != nil {
		return nil, fmt.Errorf("the saved key of %s is damaged: %v", h.Name, err)
	}
	return raw, nil
}

// attachAgentKey loads the key of h and serves it from an agent of this
// process for as long as ssh runs, the private key is only in memory
func attachAgentKey(cmd *exec.Cmd, h *Host) (func(), error) {
	noop := func() {}
	if !h.agentKey() {
		return noop, nil
	}
	raw, err := loadKey(h)
	if err != nil {
		return noop, err
	}
	keys := agent.NewKeyring()
	if err := keys.Add(agent.AddedKey{PrivateKey: raw, Comment: h.Name}); err != nil {
		return noop, err
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return noop, err
	}
	ln, sock, stop, err := listenAgent(hex.EncodeToString(b[:]))
	if err != nil {
		return noop, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				agent.ServeAgent(keys, c)
			}()
		}
	}()
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	orig := os.Getenv("SSH_AUTH_SOCK")
	kept := make([]string, 0, len(env)+2)
	for _, kv := range env {
		if !strings.HasPrefix(kv, "SSH_AUTH_SOCK=") && !strings.HasPrefix(kv, authSockOrigEnv+"=") {
			kept = append(kept, kv)
		}
	}
	cmd.Env = append(kept, "SSH_AUTH_SOCK="+sock, authSockOrigEnv+"="+orig)
	return stop, nil
}

// writePub writes the public half of a vault key next to the host file,
// it is not secret
func (s *Store) writePub(h *Host) error {
	path := s.pubPath(h)
	if !h.agentKey() && !(h.KeyMode == KeyAgent && h.KeyPub != "") {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return WriteFileAtomic(path, []byte(h.KeyPub+"\n"), 0o600)
}
