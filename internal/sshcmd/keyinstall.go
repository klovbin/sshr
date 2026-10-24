package sshcmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// DefaultKeyName is the file sshr key new writes in ~/.ssh
const DefaultKeyName = "sshr_ed25519"

// KeygenArgs is the ssh-keygen command for a new ed25519 key at path, it
// refuses a path where a key or its .pub already is, ssh-keygen asks for
// the passphrase itself so it never reaches a command line
func KeygenArgs(path, comment string, noPassphrase bool) ([]string, error) {
	for _, p := range []string{path, path + ".pub"} {
		if _, err := os.Lstat(p); err == nil {
			return nil, fmt.Errorf("%s already exists, sshr never overwrites a key, choose another name", p)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	args := []string{"-t", "ed25519", "-f", path, "-C", comment}
	if noPassphrase {
		args = append(args, "-N", "")
	}
	return args, nil
}

// installKeyScript adds the key line read from stdin to authorized_keys
// once, the key never appears on the command line, so no quoting can break
const installKeyScript = `umask 077
mkdir -p "$HOME/.ssh" && touch "$HOME/.ssh/authorized_keys" || exit 1
IFS= read -r k || exit 1
grep -qxF "$k" "$HOME/.ssh/authorized_keys" && { echo "already there"; exit 0; }
printf '%s\n' "$k" >>"$HOME/.ssh/authorized_keys" && echo "added"`

// ReadPublicKey reads one public key file in authorized_keys format and
// returns its line with a newline cut off
func ReadPublicKey(path string) (string, error) {
	b, err := os.ReadFile(ExpandHome(path))
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(b))
	if strings.Contains(line, "PRIVATE KEY") {
		return "", errors.New(path + " is a private key, give its .pub")
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err != nil || strings.Contains(line, "\n") {
		return "", fmt.Errorf("%s is not one public key", path)
	}
	return line, nil
}

// InstallKeyArgs is the ssh command that appends a public key, given on
// its stdin, to authorized_keys of h, logging in the way the host does,
// a password is asked or taken from sshr as for connect
func (e Env) InstallKeyArgs(h *Host) ([]string, error) {
	args, err := e.ConnectArgs(h)
	if err != nil {
		return nil, err
	}
	return append(args, "-T", "--", h.Dest(), "sh -c "+shQuote(installKeyScript)), nil
}
