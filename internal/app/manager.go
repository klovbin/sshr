package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// managerCLI runs the command line tool of a password manager, 1Password's
// op and Bitwarden's bw fail the same ways: not installed, no answer from a
// locked app, a message on the last line of stderr
type managerCLI struct {
	name    string // "1Password", shown in errors
	bin     *string
	missing error
	url     string
	timeout time.Duration
	// stuck is the error when the tool does not answer in time
	stuck string
	// hint may add what to do to the tool's own message
	hint func(msg string) string
}

func (m managerCLI) run(stdin []byte, args ...string) ([]byte, error) {
	bin, err := exec.LookPath(*m.bin)
	if err != nil {
		return nil, fmt.Errorf("%w: the %s CLI (%s) is not installed, see %s", m.missing, m.name, *m.bin, m.url)
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, errors.New(m.stuck)
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		if i := strings.LastIndexByte(msg, '\n'); i >= 0 {
			msg = msg[i+1:]
		}
		if msg == "" {
			msg = err.Error()
		}
		if m.hint != nil {
			msg = m.hint(msg)
		}
		return nil, fmt.Errorf("%s: %s", m.name, msg)
	}
	return stdout.Bytes(), nil
}

// publicKeyOf returns the authorized_keys line of a private key read from
// a password manager, what names the item in the error
func publicKeyOf(plain []byte, what string) (string, error) {
	raw, err := ssh.ParseRawPrivateKey(plain)
	if err != nil {
		return "", fmt.Errorf("%s is not a usable private key: %v", what, err)
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}
