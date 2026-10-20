package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// KeyAgent is the KeyMode of a host whose key stays in an ssh agent, the
// system one, the 1Password SSH agent or any agent socket, sshr only tells
// ssh which agent and which of its keys to use
const KeyAgent = "agent"

// AgentOnePassword names the 1Password SSH agent in Host.Agent
const AgentOnePassword = "1password"

// agentSocket is where the agent of a host listens, empty means the
// SSH_AUTH_SOCK of the session
func agentSocket(name string) string {
	switch name {
	case "", "system":
		return ""
	case AgentOnePassword:
		// paths from the 1Password SSH agent setup guide
		switch runtime.GOOS {
		case "darwin":
			return "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
		case "windows":
			return `\\.\pipe\openssh-ssh-agent`
		default:
			return "~/.1password/agent.sock"
		}
	}
	return name
}

// agentArgs are the ssh options for a host with KeyAgent, with a chosen
// key ssh offers only that one, servers stop after about six keys and an
// agent with more fails before it reaches the right one
func (s *Store) agentArgs(h *Host) []string {
	if h.KeyMode != KeyAgent {
		return nil
	}
	sock := agentSocket(h.Agent)
	var args []string
	if sock == "" {
		args = append(args, "-o", "IdentityAgent=SSH_AUTH_SOCK")
	} else {
		// quoted for spaces, %-tokens are expanded by ssh, ssh reads a
		// doubled backslash as one, forward slashes keep a Windows pipe
		// (//./pipe/...) and paths whole, Windows takes both kinds
		args = append(args, "-o", `IdentityAgent="`+strings.ReplaceAll(filepath.ToSlash(sock), "%", "%%")+`"`)
	}
	if h.KeyPub != "" {
		if _, err := os.Stat(s.pubPath(h)); err != nil {
			s.writePub(h)
		}
		args = append(args, "-i", s.pubPath(h), "-o", "IdentitiesOnly=yes")
	}
	return args
}

// AgentKeys lists the keys an agent offers, name is as in Host.Agent
func AgentKeys(name string) ([]*agent.Key, error) {
	sock := agentSocket(name)
	if sock == "" {
		sock = os.Getenv("SSH_AUTH_SOCK")
		if sock == "" {
			return nil, errors.New("no ssh agent in this session (SSH_AUTH_SOCK is empty)")
		}
	}
	sock = ExpandHome(sock)
	c, err := dialAgent(sock)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the agent at %s: %v", sock, err)
	}
	defer c.Close()
	return agent.NewClient(c).List()
}

// pickAgentKey finds the agent key a host names by fingerprint, comment or
// a part of either
func pickAgentKey(keys []*agent.Key, want string) (*agent.Key, error) {
	var found []*agent.Key
	for _, k := range keys {
		fp := ssh.FingerprintSHA256(k)
		if fp == want || k.Comment == want {
			return k, nil
		}
		if strings.Contains(fp, want) || strings.Contains(k.Comment, want) {
			found = append(found, k)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return nil, fmt.Errorf("the agent has no key matching %q", want)
	default:
		return nil, fmt.Errorf("%q matches %d keys in the agent, give the full fingerprint", want, len(found))
	}
}

// prepareAgentKey turns AgentKey into the public key ssh is told to use
func prepareAgentKey(h *Host) error {
	h.Agent = strings.TrimSpace(h.Agent)
	if h.Agent != "" && h.Agent != "system" && h.Agent != AgentOnePassword && !filepath.IsAbs(ExpandHome(h.Agent)) && !strings.HasPrefix(h.Agent, `\\.\pipe\`) {
		return fmt.Errorf("agent %q: use system, 1password or the full path of the agent socket", h.Agent)
	}
	if h.AgentKey == "" {
		return nil
	}
	keys, err := AgentKeys(h.Agent)
	if err != nil {
		return err
	}
	k, err := pickAgentKey(keys, strings.TrimSpace(h.AgentKey))
	if err != nil {
		return err
	}
	h.KeyPub = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
	h.AgentKey = ""
	return nil
}
