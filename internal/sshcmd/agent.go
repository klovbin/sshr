package sshcmd

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

// AgentSocket is where the agent of a host listens, empty means the
// SSH_AUTH_SOCK of the session
func AgentSocket(name string) string {
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
func (e Env) agentArgs(h *Host) []string {
	if h.KeyMode != KeyAgent {
		return nil
	}
	sock := AgentSocket(h.Agent)
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
		if _, err := os.Stat(e.Hosts.PubPath(h)); err != nil {
			e.Hosts.WritePub(h)
		}
		args = append(args, "-i", e.Hosts.PubPath(h), "-o", "IdentitiesOnly=yes")
	}
	return args
}

// AgentKeys lists the keys an agent offers, name is as in Host.Agent
func AgentKeys(name string) ([]*agent.Key, error) {
	sock := AgentSocket(name)
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

// PrepareAgentKey turns AgentKey into the public key ssh is told to use
func PrepareAgentKey(h *Host) error {
	if err := checkAgent(h); err != nil {
		return err
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
