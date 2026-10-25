package sshcmd

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"
)

// Environment of the askpass helper, ssh runs sshr itself as SSH_ASKPASS
// with the prompt as the only argument
const (
	askpassSockEnv  = "SSHR_ASKPASS"
	askpassTokenEnv = "SSHR_ASKPASS_TOKEN"
)

// AttachAuth gives ssh the secrets of h stored in sshr, a key from the
// vault through an agent of this process, a saved password through
// askpass, the returned cleanup stops both after ssh exits
func AttachAuth(cmd *exec.Cmd, h *Host) (func(), error) {
	if cmd == nil || h == nil {
		return func() {}, nil
	}
	if h.CertFile() != "" {
		return attachCert(cmd, h)
	}
	if h.ServedByAgent() {
		return attachAgentKey(cmd, h)
	}
	return attachPassword(cmd, h)
}

// attachPassword hands the saved password of h to ssh, ssh runs sshr as
// SSH_ASKPASS and the helper fetches the password from a socket this process
// serves, the password is never written to disk or put in the environment,
// the socket answers once and closes, a wrong password is not retried, hosts
// without a saved password get a no-op
func attachPassword(cmd *exec.Cmd, h *Host) (func(), error) {
	noop := func() {}
	if h.Key != "" || !h.PasswordFromSshr() {
		return noop, nil
	}
	// the ssh that will ask: the command itself, or for mosh and others the
	// ssh they start, an ssh before 8.4 ignores SSH_ASKPASS_REQUIRE and asks
	// on the terminal for a password the user did not type into sshr
	ssh := cmd.Path
	if b := strings.ToLower(filepath.Base(ssh)); b != "ssh" && b != "ssh.exe" {
		ssh, _ = SSHPath()
	}
	if ssh != "" {
		if err := askpassSupported(ssh); err != nil {
			return noop, err
		}
	}
	if err := Unlock(h); err != nil {
		// the password manager is missing or locked, ssh asks on the terminal instead,
		// with no terminal there is nobody to ask
		if h.PasswordMode == PasswordOnePassword || h.PasswordMode == PasswordBitwarden {
			if in, _, terr := openTerminal(); terr == nil {
				in.Close()
				fmt.Fprintf(os.Stderr, "sshr: %v, type the password\n", err)
				return noop, nil
			}
		}
		return noop, err
	}
	exe, err := os.Executable()
	if err != nil {
		return noop, err
	}
	sock, token, stop, err := servePassword(h.Password)
	if err != nil {
		return noop, err
	}
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	cmd.Env = append(StripAuthEnv(env),
		"SSH_ASKPASS="+exe,
		"SSH_ASKPASS_REQUIRE=force",
		askpassSockEnv+"="+sock,
		askpassTokenEnv+"="+token,
	)
	return stop, nil
}

// StripAuthEnv drops what AttachAuth set for a host from env and puts the
// user's own SSH_AUTH_SOCK back, a jump hop must not answer its password
// prompt with the password of the host behind it or offer that host's key
func StripAuthEnv(env []string) []string {
	out := make([]string, 0, len(env))
	orig, hasOrig := "", false
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, authSockOrigEnv+"="); ok {
			orig, hasOrig = v, true
		}
	}
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		switch name {
		case "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", askpassSockEnv, askpassTokenEnv, authSockOrigEnv:
			continue
		case "SSH_AUTH_SOCK":
			if hasOrig {
				continue
			}
		}
		out = append(out, kv)
	}
	if hasOrig && orig != "" {
		out = append(out, "SSH_AUTH_SOCK="+orig)
	}
	return out
}

// servePassword listens on a unix socket in a 0700 directory and gives
// password once to a client that sends token
func servePassword(password string) (sock, token string, stop func(), err error) {
	dir, err := ControlDir()
	cleanDir := func() {}
	if err != nil {
		if dir, err = os.MkdirTemp("", "sshr-"); err != nil {
			return "", "", nil, err
		}
		cleanDir = func() { os.Remove(dir) }
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		cleanDir()
		return "", "", nil, err
	}
	token = hex.EncodeToString(b[:])
	sock = filepath.Join(dir, "ap-"+token[:12])
	ln, err := net.Listen("unix", sock)
	if err != nil {
		cleanDir()
		return "", "", nil, err
	}
	go func() {
		defer ln.Close()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.SetDeadline(time.Now().Add(5 * time.Second))
			line, _ := bufio.NewReader(io.LimitReader(c, 128)).ReadString('\n')
			if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(line)), []byte(token)) == 1 {
				io.WriteString(c, password+"\n")
				c.Close()
				return
			}
			c.Close()
		}
	}()
	stop = func() {
		ln.Close()
		os.Remove(sock)
		cleanDir()
	}
	return sock, token, stop, nil
}

// IsAskpassCall tells whether ssh started this process as SSH_ASKPASS
func IsAskpassCall(args []string) bool {
	return len(args) == 1 && os.Getenv(askpassSockEnv) != ""
}

// isPasswordPrompt matches "user@host's password: " and the
// keyboard-interactive "(user@host) Password: "
func isPasswordPrompt(prompt string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(prompt)), "password:")
}

// RunAskpass answers one ssh prompt and returns the exit code, a password
// prompt gets the saved password, any other prompt (host key, key
// passphrase, one-time code) is asked on the terminal, exit 1 tells ssh no
// answer was given
func RunAskpass(prompt string) int {
	if isPasswordPrompt(prompt) {
		pw, err := fetchPassword(os.Getenv(askpassSockEnv), os.Getenv(askpassTokenEnv))
		if err != nil {
			return 1
		}
		fmt.Println(pw)
		return 0
	}
	answer, err := AskTerminal(prompt)
	if err != nil {
		return 1
	}
	fmt.Println(answer)
	return 0
}

// fetchPassword gets the password from the socket of attachPassword,
// after the first answer the socket is closed and this fails
func fetchPassword(sock, token string) (string, error) {
	c, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, token+"\n"); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return "", errors.New("no password from sshr")
	}
	return strings.TrimSuffix(line, "\n"), nil
}

// AskTerminal shows prompt on the terminal and reads the answer, hidden
// unless it is a yes/no question, it works when stdin is a pipe
func AskTerminal(prompt string) (string, error) {
	in, out, err := openTerminal()
	if err != nil {
		return "", err
	}
	defer in.Close()
	if out != in {
		defer out.Close()
	}
	fmt.Fprint(out, prompt)
	p := strings.TrimSpace(prompt)
	if strings.HasSuffix(p, "?") || strings.Contains(p, "yes/no") {
		line, err := bufio.NewReader(in).ReadString('\n')
		return strings.TrimRight(line, "\r\n"), err
	}
	b, err := term.ReadPassword(int(in.Fd()))
	fmt.Fprintln(out)
	return string(b), err
}

// Unlock fills h.Password from the vault, 1Password or Bitwarden before
// connecting, a host without a saved password is left as it is
func Unlock(h *Host) error {
	if h.Password != "" {
		return nil
	}
	switch h.PasswordMode {
	case PasswordOnePassword:
		pw, err := opRead(h.PasswordRef)
		if err != nil {
			return err
		}
		h.Password = string(pw)
		return nil
	case PasswordBitwarden:
		pw, err := bwPassword(h.PasswordRef)
		if err != nil {
			return err
		}
		h.Password = string(pw)
		return nil
	}
	return unlockSaved(h)
}
