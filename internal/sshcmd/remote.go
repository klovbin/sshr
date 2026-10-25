package sshcmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

// RemoteResult is what a command run with RunRemote gave back
type RemoteResult struct {
	Stdout, Stderr []byte
	// ExitCode is the exit code of the command, 255 when ssh itself failed
	ExitCode int
	// Truncated is set when output went past the limit and was cut
	Truncated bool
}

// remoteOutputMax caps what RunRemote keeps of each stream
const remoteOutputMax = 64 << 10

// capWriter keeps the first max bytes and counts the rest
type capWriter struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	if room := w.max - w.buf.Len(); room > 0 {
		if len(p) > room {
			w.buf.Write(p[:room])
			w.over = true
		} else {
			w.buf.Write(p)
		}
	} else if len(p) > 0 {
		w.over = true
	}
	return len(p), nil
}

// remoteTimeoutScript runs "$1" under timeout(1) on the server when it has
// one, without a terminal sshd does not stop the command when ssh goes away,
// and a command killed only on this side keeps running there
func remoteTimeoutScript(secs int) string {
	return fmt.Sprintf(`if command -v timeout >/dev/null 2>&1; then exec timeout -k 5 %d sh -c "$1"; fi; exec sh -c "$1"`, secs)
}

// RunRemote runs command with sh on h without a terminal and returns its
// output, like an upload from the app, a key, an agent or a saved password
// is used, a host that asks for its password every time fails with
// ErrAsksPassword, the command is stopped after timeout on the server too
func (e Env) RunRemote(h *Host, command string, stdin io.Reader, timeout time.Duration) (*RemoteResult, error) {
	sshPath, err := SSHPath()
	if err != nil {
		return nil, err
	}
	if h.PasswordMode == PasswordAsk {
		return nil, ErrAsksPassword
	}
	args, err := e.ConnectArgs(h)
	if err != nil {
		return nil, err
	}
	if !h.PasswordFromSshr() {
		args = append(args, "-o", "BatchMode=yes")
	}
	secs := int(timeout / time.Second)
	if secs < 1 {
		secs = 1
	}
	// the login shell may be fish, so the wrapper runs under sh
	remote := "sh -c " + shQuote(remoteTimeoutScript(secs)) + " sshr " + shQuote(command)
	args = append(args, "-o", "ConnectTimeout=10", "-T", "--", h.Dest(), remote)
	// the server stops the command first, this side waits a little longer
	ctx, cancel := context.WithTimeout(context.Background(), timeout+15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sshPath, args...)
	// jump hops run as separate ssh processes, they read this too
	cmd.Env = append(os.Environ(), "SSHR_BATCH=1")
	if stdin == nil {
		stdin = bytes.NewReader(nil)
	}
	cmd.Stdin = stdin
	out := &capWriter{max: remoteOutputMax}
	errOut := &capWriter{max: remoteOutputMax}
	cmd.Stdout, cmd.Stderr = out, errOut
	cleanup, err := AttachAuth(cmd, h)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	runErr := cmd.Run()
	res := &RemoteResult{Stdout: out.buf.Bytes(), Stderr: errOut.buf.Bytes(), Truncated: out.over || errOut.over}
	var exitErr *exec.ExitError
	switch {
	case ctx.Err() != nil:
		return res, errors.New("the command did not finish in time and the connection was dropped")
	case errors.As(runErr, &exitErr):
		res.ExitCode = exitErr.ExitCode()
		// 124 is timeout(1) stopping the command
		if res.ExitCode == 124 {
			return res, fmt.Errorf("the command did not finish in %d s and was stopped on the server", secs)
		}
	case runErr != nil:
		return nil, runErr
	}
	return res, nil
}
