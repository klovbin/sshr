package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode"

	"sshr.dev/internal/vault"
)

// The vault asks a FIDO2 token for its hmac-secret through the tools of
// libfido2 (fido2-token, fido2-cred, fido2-assert), sshr links no C, the
// tools print nothing while they wait for a touch, so sshr says it, they
// run without a terminal of their own, an MCP server or a GUI started from
// a terminal would otherwise have them ask in someone else's terminal

const (
	// fido2TouchWait bounds a question that waits for a touch
	fido2TouchWait = 45 * time.Second
	// fido2QuickWait bounds a question that needs no touch
	fido2QuickWait = 10 * time.Second
)

// fido2Command makes the command of a libfido2 tool, a test points it at
// a fake token
var fido2Command = func(ctx context.Context, tool string, args ...string) (*exec.Cmd, error) {
	path, err := exec.LookPath(tool)
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not installed, it comes with libfido2 (fido2-tools on Debian and Ubuntu, libfido2 in Homebrew and nixpkgs)", vault.ErrNoToken, tool)
	}
	cmd := exec.CommandContext(ctx, path, args...)
	detachTerminal(cmd)
	return cmd, nil
}

// fido2Say tells the person what the token waits for and which sshr asks,
// on stderr, a touch given for something else must not open the vault
// unseen
var fido2Say = func(msg string) {
	who := "sshr"
	if len(os.Args) > 1 {
		who += " " + os.Args[1]
	}
	fmt.Fprintf(os.Stderr, "sshr: %s (asked by %s, pid %d)\n", msg, who, os.Getpid())
}

// runFIDO2 runs tool with input in a parameter file, device last, and
// gives the lines it printed
func runFIDO2(wait time.Duration, tool string, input []string, args []string, device, pin string) ([]string, error) {
	dir, err := os.MkdirTemp("", "sshr-fido2-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	params := filepath.Join(dir, "params")
	if err := os.WriteFile(params, []byte(strings.Join(input, "\n")+"\n"), 0o600); err != nil {
		return nil, err
	}
	// Ctrl-C ends the wait, the tool runs in a session of its own and
	// would not get the signal, it would keep waiting for a stray touch
	sig, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(sig, wait)
	defer cancel()
	cmd, err := fido2Command(ctx, tool, append(append(args, "-i", params, "--"), device)...)
	if err != nil {
		return nil, err
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	// without a terminal the tools read the PIN from stdin, without a PIN
	// stdin stays empty and a question for one ends at once
	if pin != "" {
		cmd.Stdin = strings.NewReader(pin + "\n")
	}
	err = cmd.Run()
	switch {
	case sig.Err() != nil:
		return nil, errors.New("stopped while the security key waited for a touch")
	case ctx.Err() == context.DeadlineExceeded:
		return nil, fmt.Errorf("%w: the security key got no touch in %s", vault.ErrNoToken, wait)
	case err != nil:
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, fmt.Errorf("%s: %v %s", tool, err, cleanText(msg))
	}
	return strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n"), nil
}

// fido2Devices lists the tokens the system sees, a device path per token
func fido2Devices() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), fido2QuickWait)
	defer cancel()
	cmd, err := fido2Command(ctx, "fido2-token", "-L")
	if err != nil {
		return nil, err
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("fido2-token -L: %v", err)
	}
	var devs []string
	for _, line := range strings.Split(string(out), "\n") {
		// "/dev/hidraw5: vendor=0x1050, product=0x0407 (Yubico YubiKey)",
		// a line of another shape is not a device, a path that starts with
		// "-" would read as an option
		dev, _, ok := strings.Cut(line, ": ")
		if ok && fido2DevicePath(dev) {
			devs = append(devs, dev)
		}
	}
	return devs, nil
}

// fido2DevicePath tells a device path of libfido2: a hidraw or uhid node
// on Linux and the BSDs, an IOKit entry on macOS, a PC/SC reader
func fido2DevicePath(dev string) bool {
	for _, p := range []string{"/dev/", "ioreg://", "pcsc://", "nfc:", "hid:"} {
		if strings.HasPrefix(dev, p) {
			return !strings.ContainsAny(dev, "\n\r")
		}
	}
	return false
}

// cleanText puts ? for control characters, what a tool prints goes to a
// terminal
func cleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Bidi_Control) {
			return '?'
		}
		return r
	}, s)
}

// noCredential tells the error of a token that does not hold the
// credential from a tool or a token that failed
func noCredential(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "NO_CREDENTIALS") || strings.Contains(err.Error(), "INVALID_CREDENTIAL"))
}

func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// fido2Assert asks device for an assertion of cred, with the hmac-secret
// of salt when salt is set, touch asks for user presence, the output is
// read strictly, a line missing or out of place is an error and never a
// secret
func fido2Assert(device, rp string, cred, salt []byte, touch, uv bool, pin string) ([]byte, error) {
	cdh, err := randomB64(32)
	if err != nil {
		return nil, err
	}
	input := []string{cdh, rp, base64.StdEncoding.EncodeToString(cred)}
	args := []string{"-G", "-t", fmt.Sprintf("up=%t", touch), "-t", "uv=false"}
	if uv {
		// -v asks the PIN and user verification together
		args = []string{"-G", "-t", fmt.Sprintf("up=%t", touch), "-v"}
	}
	want := 4
	if salt != nil {
		input = append(input, base64.StdEncoding.EncodeToString(salt))
		args = append(args, "-h")
		want = 5
	}
	wait := fido2QuickWait
	if touch {
		wait = fido2TouchWait
	}
	lines, err := runFIDO2(wait, "fido2-assert", input, args, device, pin)
	if err != nil {
		return nil, err
	}
	// client data hash, relying party, authenticator data, signature and,
	// with -h, the hmac-secret
	if len(lines) != want || lines[0] != cdh || lines[1] != rp {
		return nil, fmt.Errorf("fido2-assert answered %d lines that do not match the question", len(lines))
	}
	if salt == nil {
		return nil, nil
	}
	secret, err := base64.StdEncoding.DecodeString(lines[4])
	if err != nil || len(secret) != 32 {
		return nil, errors.New("fido2-assert gave no hmac-secret of 32 bytes, the token may not support hmac-secret")
	}
	return secret, nil
}

// askFIDO2 finds the plugged token that holds the credential, without a
// touch, and asks it for the hmac-secret
func askFIDO2(r vault.TokenRequest) ([]byte, error) {
	if runtime.GOOS == "windows" {
		return nil, fmt.Errorf("%w: a key on a FIDO2 token opens the vault on Linux and macOS, not on Windows yet", vault.ErrNoToken)
	}
	devs, err := fido2Devices()
	if err != nil {
		return nil, err
	}
	if len(devs) == 0 {
		return nil, fmt.Errorf("%w: no security key is plugged in", vault.ErrNoToken)
	}
	var failed error
	for _, dev := range devs {
		if _, err := fido2Assert(dev, r.RP, r.Cred, nil, false, false, ""); err != nil {
			if !noCredential(err) {
				failed = err
			}
			continue
		}
		name := cleanText(r.Label)
		if name == "" {
			name = dev
		}
		pin := ""
		if r.UV {
			if pin, err = askPIN(dev, name); err != nil {
				return nil, err
			}
		}
		fido2Say("touch the security key " + name + " to open the vault")
		secret, err := fido2Assert(dev, r.RP, r.Cred, r.Salt, true, r.UV, pin)
		if r.UV {
			err = pinFailure(err)
		}
		return secret, err
	}
	if failed != nil {
		return nil, fmt.Errorf("%w: no plugged security key answered as one that holds the credential of this vault: %v", vault.ErrNoToken, failed)
	}
	return nil, fmt.Errorf("%w: none of the plugged security keys holds the credential of this vault", vault.ErrNoToken)
}

// fido2PIN asks the PIN of a security key on the terminal or from the
// program in SSHR_PIN_ASKPASS, never from SSHR_ASKPASS, a helper that
// prints the vault passphrase would hand it to the key as a PIN and burn
// its tries, a key blocks itself after a few wrong PINs, so it is asked
// once and never tried again on its own
var fido2PIN = func(name string) (string, error) {
	prompt := "PIN of the security key " + name + ": "
	var pin string
	var err error
	switch prog := os.Getenv("SSHR_PIN_ASKPASS"); {
	case prog != "":
		ctx, cancel := context.WithTimeout(context.Background(), askpassWait)
		defer cancel()
		var out []byte
		if out, err = exec.CommandContext(ctx, prog, prompt).Output(); err == nil {
			pin = strings.TrimRight(string(out), "\r\n")
		}
	case NoTerminalPrompts:
		err = errors.New("the vault needs the PIN of its security key and there is no terminal here, set SSHR_PIN_ASKPASS to a program that prints it")
	default:
		pin, err = AskTerminal(prompt)
	}
	if err != nil {
		return "", fmt.Errorf("%w: %v", vault.ErrTokenPIN, err)
	}
	if len(pin) < 4 || len(pin) > 63 || strings.ContainsAny(pin, "\r\n") {
		return "", fmt.Errorf("%w: a PIN of a security key is one line of 4 to 63 characters", vault.ErrTokenPIN)
	}
	return pin, nil
}

// fido2PINRetries reads how many PIN tries the key has left, ok is false
// when it does not say
func fido2PINRetries(device string) (n int, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), fido2QuickWait)
	defer cancel()
	cmd, err := fido2Command(ctx, "fido2-token", "-I", "--", device)
	if err != nil {
		return 0, false
	}
	out, err := cmd.Output()
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if v, found := strings.CutPrefix(line, "pin retries: "); found {
			if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

// fido2PINMinRetries is the fewest PIN tries a key may have left for sshr
// to ask its PIN, below that the person unlocks it with its own tools
const fido2PINMinRetries = 4

// askPIN asks the PIN of the key at device, refused when the key has few
// tries left
func askPIN(device, name string) (string, error) {
	if n, ok := fido2PINRetries(device); ok && n < fido2PINMinRetries {
		return "", fmt.Errorf("%w: the security key %s has %d PIN tries left, sshr does not spend them, enter the PIN with the tools of the key first", vault.ErrTokenPIN, name, n)
	}
	return fido2PIN(name)
}

// pinFailure marks the error of a tool that refused the PIN as one, the
// vault then asks no PIN again in this run
func pinFailure(err error) error {
	if err == nil {
		return nil
	}
	for _, s := range []string{"PIN_INVALID", "PIN_AUTH_BLOCKED", "PIN_BLOCKED", "invalid PIN length"} {
		if strings.Contains(err.Error(), s) {
			return fmt.Errorf("%w: %v", vault.ErrTokenPIN, err)
		}
	}
	return err
}

// pinAsked tells the error of a tool that wanted a PIN and got none
func pinAsked(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "invalid PIN length") || strings.Contains(err.Error(), "readpassphrase") || strings.Contains(err.Error(), "PIN_REQUIRED"))
}

// enrolFIDO2 makes a credential with hmac-secret on the one plugged token
// and asks it for its first secret, two touches, a key with a PIN set may
// want the PIN to make a credential, it is asked then, with uv the PIN is
// asked from the start and every time the vault opens
func enrolFIDO2(rp string, salt []byte, uv bool, known [][]byte) (cred, secret []byte, err error) {
	if runtime.GOOS == "windows" {
		return nil, nil, errors.New("a key on a FIDO2 token opens the vault on Linux and macOS, not on Windows yet")
	}
	devs, err := fido2Devices()
	if err != nil {
		return nil, nil, err
	}
	if len(devs) != 1 {
		return nil, nil, fmt.Errorf("%d security keys are plugged in, plug in only the one to add", len(devs))
	}
	// the same key twice would pass for two keys and let the last other
	// way in go
	for _, c := range known {
		if _, err := fido2Assert(devs[0], rp, c, nil, false, false, ""); err == nil {
			return nil, nil, errors.New("this security key opens the vault already, plug in another one")
		}
	}
	cdh, err := randomB64(32)
	if err != nil {
		return nil, nil, err
	}
	user, err := randomB64(16)
	if err != nil {
		return nil, nil, err
	}
	pin := ""
	args := []string{"-M", "-h"}
	if uv {
		// -t pin=true sends the PIN at once, -v asks user verification
		// first, which a CTAP 2.0 key without a PIN token refuses
		args = append(args, "-t", "pin=true")
		if pin, err = askPIN(devs[0], devs[0]); err != nil {
			return nil, nil, err
		}
	}
	input := []string{cdh, rp, "sshr vault", user}
	fido2Say("touch the security key to make its credential for the vault")
	lines, err := runFIDO2(fido2TouchWait, "fido2-cred", input, args, devs[0], pin)
	if pinAsked(err) && pin == "" {
		// the key asked its PIN before any touch, the touch is still to come
		if pin, err = askPIN(devs[0], devs[0]); err != nil {
			return nil, nil, err
		}
		fido2Say("touch the security key to make its credential for the vault")
		lines, err = runFIDO2(fido2TouchWait, "fido2-cred", input, args, devs[0], pin)
	}
	if err != nil {
		return nil, nil, pinFailure(err)
	}
	// client data hash, relying party, format, authenticator data,
	// credential ID, then signature and certificate
	if len(lines) < 5 || lines[0] != cdh || lines[1] != rp {
		return nil, nil, errors.New("fido2-cred answered lines that do not match the question")
	}
	if cred, err = base64.StdEncoding.DecodeString(lines[4]); err != nil || len(cred) == 0 {
		return nil, nil, errors.New("fido2-cred gave no credential ID")
	}
	fido2Say("touch the security key again to get its secret")
	if !uv {
		pin = ""
	}
	secret, err = fido2Assert(devs[0], rp, cred, salt, true, uv, pin)
	return cred, secret, pinFailure(err)
}
