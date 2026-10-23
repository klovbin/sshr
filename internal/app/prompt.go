package app

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// askpassWait bounds a SSHR_ASKPASS helper that never answers
const askpassWait = time.Minute

// NoTerminalPrompts is set by front ends that own stdin and stdout (mcp),
// the passphrase is then only taken from SSHR_ASKPASS
var NoTerminalPrompts bool

// promptPassphrase gets the passphrase: from the program in SSHR_ASKPASS
// (the app or a script), else on the terminal, never on stdin
func promptPassphrase(prompt string) (string, error) {
	if prog := os.Getenv("SSHR_ASKPASS"); prog != "" {
		ctx, cancel := context.WithTimeout(context.Background(), askpassWait)
		defer cancel()
		var stderr bytes.Buffer
		cmd := exec.CommandContext(ctx, prog, prompt)
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("%w: SSHR_ASKPASS failed: %v %s", ErrNoPassphrase, err, strings.TrimSpace(stderr.String()))
		}
		return strings.TrimRight(string(out), "\r\n"), nil
	}
	if NoTerminalPrompts {
		return "", fmt.Errorf("%w: the vault needs its passphrase and there is no terminal here, set SSHR_ASKPASS to a program that prints it", ErrNoPassphrase)
	}
	p, err := AskTerminal(prompt)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrNoPassphrase, err)
	}
	return p, nil
}
