package app

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// ErrAsksPassword means the host asks for its password every time and there
// is no terminal to ask in
var ErrAsksPassword = errors.New("asks_password")

// UploadTTL is how long an uploaded image stays on the server. It is meant
// to be read once (by a person or a remote tool), not stored there.
const UploadTTL = 15 * time.Minute

// SSHArgs returns the ssh options for a host: key, password prefs, and port.
func SSHArgs(h *Host) []string {
	args := []string{}
	if h.Key != "" {
		args = append(args, "-i", h.Key)
	} else if h.PasswordMode != "" {
		args = append(args,
			// servers that log in through PAM ask with keyboard-interactive,
			// the prompt is "(user@host) Password:"
			"-o", "PreferredAuthentications=keyboard-interactive,password",
			"-o", "PubkeyAuthentication=no",
		)
		if h.PasswordFromSshr() {
			// a saved password is the same every time, retrying it only adds
			// failures for fail2ban to count
			args = append(args, "-o", "NumberOfPasswordPrompts=1")
		}
	}
	return append(args, "-p", strconv.Itoa(h.Port))
}

// UploadImage copies data to ~/.cache/sshr/pasted/ on the host over a
// separate ssh and returns the path there. The file is removed after
// UploadTTL by a detached sleep; each upload also sweeps older files in case
// that sleep was killed by a logout.
//
// batch disables prompts on the terminal (ssh -o BatchMode=yes), set it when
// there is no terminal to ask in, as in the GUI, a saved password is still
// used, a host that asks for its password every time fails with
// ErrAsksPassword, the upload goes through the host's jump hosts like a
// normal connection
func (s *Store) UploadImage(h *Host, data []byte, ext string, batch bool) (string, error) {
	if _, err := SSHPath(); err != nil {
		return "", err
	}
	// the name goes into the sh -c script on the server, an extension
	// like $(cmd) would run there
	ext = strings.ToLower(ext)
	if !uploadExtRe.MatchString(ext) {
		return "", fmt.Errorf("file extension %q: only letters and digits, up to 10", ext)
	}
	name := fmt.Sprintf("paste-%d.%s", time.Now().UnixMilli(), ext)
	mins := int(UploadTTL / time.Minute)
	script := strings.Join([]string{
		`d="$HOME/.cache/sshr/pasted"`,
		`mkdir -p "$d" || exit 1`,
		`f="$d/` + name + `"`,
		`cat > "$f" || exit 1`,
		fmt.Sprintf(`find "$d" -maxdepth 1 -name 'paste-*' -mmin +%d -exec rm -f {} + 2>/dev/null`, mins),
		fmt.Sprintf(`nohup sh -c 'sleep %d; rm -f "$1"' _ "$f" </dev/null >/dev/null 2>&1 &`, mins*60),
		`printf "%s" "$f"`,
	}, "\n")

	args, err := s.ConnectArgs(h)
	if err != nil {
		return "", err
	}
	if batch {
		if h.PasswordMode == PasswordAsk {
			return "", ErrAsksPassword
		}
		// BatchMode turns askpass off too, a saved password still goes
		// through it, the askpass helper refuses any other prompt when
		// there is no terminal
		if !h.PasswordFromSshr() {
			args = append(args, "-o", "BatchMode=yes")
		}
	}
	// The login shell on the server may be fish, so the script runs under sh.
	args = append(args, "-o", "ConnectTimeout=10", "-T", "--", h.Dest(), "sh -c "+shQuote(script))

	cmd := sshCommand(args...)
	if batch {
		// Jump hops run as separate ssh processes, they read this too
		cmd.Env = append(os.Environ(), "SSHR_BATCH=1")
	}
	cmd.Stdin = bytes.NewReader(data)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cleanup, err := AttachAuth(cmd, h)
	if err != nil {
		return "", err
	}
	defer cleanup()
	err = cmd.Run()
	// the path is the last line and must be the file the script wrote, a
	// login script or a hostile server may print more, that is not handed
	// on as the answer
	out := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	remote := strings.TrimSpace(out[len(out)-1])
	if err == nil && len(remote) <= uploadPathMax && strings.HasPrefix(remote, "/") &&
		strings.HasSuffix(remote, "/.cache/sshr/pasted/"+name) && strings.IndexFunc(remote, unicode.IsControl) < 0 {
		return remote, nil
	}
	msg := strings.TrimSpace(stderr.String())
	if msg != "" {
		lines := strings.Split(msg, "\n")
		msg = strings.TrimSpace(lines[len(lines)-1])
	} else if err != nil {
		msg = err.Error()
	} else {
		msg = "server returned no path of the uploaded file (is sh available there?)"
	}
	return "", fmt.Errorf("upload to %s failed: %s", h.Name, msg)
}

// uploadPathMax caps the path a server answers, a home folder is short,
// a long answer carries something else before the file name
const uploadPathMax = 512

// uploadExtRe is what an upload's file extension may be
var uploadExtRe = regexp.MustCompile(`^[a-z0-9]{1,10}$`)

// shQuote wraps s in single quotes for a POSIX shell.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
