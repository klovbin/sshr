package sshcmd

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"sshr.dev/internal/hosts"
)

// vaultKeyArgs are the ssh options for a host with a vault key, the key
// itself comes from the agent AttachAuth starts, the user's own agent and
// key files are not offered, agent forwarding is off so the server never
// reaches the key
func (e Env) vaultKeyArgs(h *Host) []string {
	if !h.ServedByAgent() {
		return nil
	}
	// the host file may come from a copy without its .pub next to it
	if _, err := os.Stat(e.Hosts.PubPath(h)); err != nil {
		e.Hosts.WritePub(h)
	}
	return []string{
		"-i", e.Hosts.PubPath(h),
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=SSH_AUTH_SOCK",
		"-o", "ForwardAgent=no",
	}
}

// authSockOrigEnv keeps the user's SSH_AUTH_SOCK while it points at the
// agent of a vault key, a jump hop restores it
const authSockOrigEnv = "SSHR_AUTH_SOCK_ORIG"

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
	if typ := hosts.HardwareKeyType(plain); typ != "" {
		return nil, fmt.Errorf("the key of %s is the handle of a hardware key (%s), sshr cannot serve it from its agent, save the handle as a key file and keep the token plugged in", h.Name, typ)
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
	if !h.ServedByAgent() {
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
	return serveAgent(cmd, keys, h.Name)
}

// serveAgent serves keys from an agent of this process to cmd for as long
// as it runs, only to ssh and the programs sshr started, name is the host
// a refusal is said for
func serveAgent(cmd *exec.Cmd, keys agent.Agent, name string) (func(), error) {
	noop := func() {}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return noop, err
	}
	ln, sock, stop, err := listenAgent(hex.EncodeToString(b[:]))
	if err != nil {
		return noop, err
	}
	var refused sync.Once
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				// only ssh and the programs sshr started get the key, another
				// program of the user could log in elsewhere with it, the first
				// refusal is said, ssh would only report the key as refused,
				// the check runs per connection, a flood of refused ones does
				// not hold up the next
				if err := checkAgentPeer(c, agentRoot(cmd)); err != nil {
					refused.Do(func() {
						fmt.Fprintf(os.Stderr, "sshr: the agent of %s refused a connection: %v\n", name, err)
					})
					return
				}
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
