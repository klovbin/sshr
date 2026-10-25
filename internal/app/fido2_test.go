//go:build !windows

package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"sshr.dev/internal/vault"
)

// TestFIDO2Helper is the fake libfido2 tool the tests run, not a test: it
// answers as a token whose hmac-secret is an HMAC over the credential and
// the salt, SSHR_FAKE_FIDO2 picks a broken answer
func TestFIDO2Helper(t *testing.T) {
	mode := os.Getenv("SSHR_FAKE_FIDO2")
	if mode == "" {
		return
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	tool, args := args[0], args[1:]
	if tool == "fido2-token" && len(args) > 0 && args[0] == "-I" {
		retries := "8"
		if mode == "few-tries" {
			retries = "2"
		}
		fmt.Println("pin retries: " + retries)
		os.Exit(0)
	}
	if tool == "fido2-token" {
		// a line of another shape and a path that reads as an option are
		// not devices
		fmt.Println("-o/tmp/x: evil")
		fmt.Println("garbage")
		fmt.Println("/dev/hidraw9: vendor=0x1050, product=0x0407 (Fake Key)")
		os.Exit(0)
	}
	var in []string
	hmacOn, verify := false, false
	for i, a := range args {
		switch a {
		case "-i":
			b, _ := os.ReadFile(args[i+1])
			in = strings.Split(strings.TrimRight(string(b), "\n"), "\n")
		case "-h":
			hmacOn = true
		case "-v", "pin=true":
			verify = true
		}
	}
	// a PIN comes on stdin, as from readpassphrase without a terminal
	stdin, _ := io.ReadAll(os.Stdin)
	pinGiven := strings.TrimSpace(string(stdin)) == "1234"
	if (verify || tool == "fido2-cred" && mode == "pin-cred") && !pinGiven {
		fmt.Fprintln(os.Stderr, tool+": invalid PIN length")
		os.Exit(1)
	}
	switch tool {
	case "fido2-cred":
		cred := base64.StdEncoding.EncodeToString([]byte("credential-id-of-the-fake"))
		fmt.Printf("%s\n%s\npacked\nAUTHDATA\n%s\nSIG\n", in[0], in[1], cred)
	case "fido2-assert":
		if mode == "other-cred" {
			fmt.Fprintln(os.Stderr, "no credentials")
			os.Exit(1)
		}
		cdh := in[0]
		if mode == "bad-echo" {
			cdh = "AAAA"
		}
		fmt.Printf("%s\n%s\nAUTHDATA\nSIG\n", cdh, in[1])
		if hmacOn && mode != "no-hmac" {
			cred, _ := base64.StdEncoding.DecodeString(in[2])
			salt, _ := base64.StdEncoding.DecodeString(in[3])
			m := hmac.New(sha256.New, []byte("device secret"))
			m.Write(cred)
			m.Write(salt)
			if verify {
				m.Write([]byte{1})
			}
			fmt.Println(base64.StdEncoding.EncodeToString(m.Sum(nil)))
		}
	}
	os.Exit(0)
}

// fakeFIDO2 points the libfido2 tools at TestFIDO2Helper in mode
func fakeFIDO2(t *testing.T, mode string) {
	t.Helper()
	old, oldSay := fido2Command, fido2Say
	fido2Command = func(ctx context.Context, tool string, args ...string) (*exec.Cmd, error) {
		cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=TestFIDO2Helper", "--", tool}, args...)...)
		cmd.Env = append(os.Environ(), "SSHR_FAKE_FIDO2="+mode)
		detachTerminal(cmd)
		return cmd, nil
	}
	fido2Say = func(string) {}
	t.Cleanup(func() { fido2Command, fido2Say = old, oldSay })
}

// enrolment and a later question give the same secret, the token that
// holds the credential is found without a touch
func TestFIDO2EnrolAndAsk(t *testing.T) {
	fakeFIDO2(t, "ok")
	salt := bytes.Repeat([]byte{1}, 32)
	cred, secret, err := enrolFIDO2("sshr:vault", salt, false, nil)
	if err != nil || len(secret) != 32 {
		t.Fatalf("enrol: %v", err)
	}
	got, err := askFIDO2(vault.TokenRequest{RP: "sshr:vault", Cred: cred, Salt: salt})
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("ask: %v", err)
	}
	// the key that holds a credential of the vault is enrolled already
	if _, _, err := enrolFIDO2("sshr:vault", salt, false, [][]byte{cred}); err == nil || !strings.Contains(err.Error(), "already") {
		t.Errorf("the same key twice: %v", err)
	}
	devs, err := fido2Devices()
	if err != nil || len(devs) != 1 || devs[0] != "/dev/hidraw9" {
		t.Errorf("devices %q %v", devs, err)
	}
}

// an answer without the hmac-secret line or with another client data hash
// is an error and never a secret, a token without the credential is no
// token, a missing tool is no token
func TestFIDO2StrictAnswers(t *testing.T) {
	req := vault.TokenRequest{RP: "sshr:vault", Cred: []byte("c"), Salt: bytes.Repeat([]byte{2}, 32)}
	for _, mode := range []string{"no-hmac", "bad-echo"} {
		fakeFIDO2(t, mode)
		if got, err := askFIDO2(req); err == nil {
			t.Errorf("%s gave a secret %x", mode, got)
		}
	}
	fakeFIDO2(t, "other-cred")
	if _, err := askFIDO2(req); !errors.Is(err, vault.ErrNoToken) {
		t.Errorf("a token without the credential: %v", err)
	}
	fido2Command = func(context.Context, string, ...string) (*exec.Cmd, error) {
		return nil, fmt.Errorf("%w: not installed", vault.ErrNoToken)
	}
	if _, err := askFIDO2(req); !errors.Is(err, vault.ErrNoToken) {
		t.Errorf("a missing tool: %v", err)
	}
}

// a key with a PIN set asks it to make a credential, sshr asks the person
// once then, with uv the PIN is asked at enrolment and at every open and
// the secret is the one with user verification
func TestFIDO2PIN(t *testing.T) {
	asked := 0
	old := fido2PIN
	fido2PIN = func(string) (string, error) { asked++; return "1234", nil }
	t.Cleanup(func() { fido2PIN = old })
	salt := bytes.Repeat([]byte{3}, 32)

	fakeFIDO2(t, "pin-cred")
	cred, secret, err := enrolFIDO2("sshr:vault", salt, false, nil)
	if err != nil || asked != 1 {
		t.Fatalf("a key that wants its PIN to make a credential: %v, asked %d", err, asked)
	}
	if got, err := askFIDO2(vault.TokenRequest{RP: "sshr:vault", Cred: cred, Salt: salt}); err != nil || !bytes.Equal(got, secret) || asked != 1 {
		t.Fatalf("touch only after that: %v, asked %d", err, asked)
	}

	fakeFIDO2(t, "ok")
	asked = 0
	cred, uvSecret, err := enrolFIDO2("sshr:vault", salt, true, nil)
	if err != nil || asked != 1 {
		t.Fatalf("enrolment with a PIN: %v, asked %d", err, asked)
	}
	got, err := askFIDO2(vault.TokenRequest{RP: "sshr:vault", Cred: cred, Salt: salt, UV: true})
	if err != nil || !bytes.Equal(got, uvSecret) || asked != 2 {
		t.Fatalf("an open with a PIN: %v, asked %d", err, asked)
	}
	if bytes.Equal(uvSecret, secret) {
		t.Error("the secret with user verification is the one without")
	}
}

// a key with few PIN tries left is not asked, the PIN never comes from the
// helper of the vault passphrase, a failed PIN is marked as one
func TestFIDO2PINSafety(t *testing.T) {
	fakeFIDO2(t, "few-tries")
	old := fido2PIN
	asked := 0
	fido2PIN = func(string) (string, error) { asked++; return "1234", nil }
	if _, err := askPIN("/dev/hidraw9", "yubi"); !errors.Is(err, vault.ErrTokenPIN) || asked != 0 {
		t.Errorf("a key with 2 tries left: %v, asked %d", err, asked)
	}
	fido2PIN = old
	t.Cleanup(func() { fido2PIN = old; NoTerminalPrompts = false })

	t.Setenv("SSHR_ASKPASS", "/bin/echo")
	NoTerminalPrompts = true
	if _, err := fido2PIN("yubi"); !errors.Is(err, vault.ErrTokenPIN) || !strings.Contains(err.Error(), "SSHR_PIN_ASKPASS") {
		t.Errorf("the PIN from the passphrase helper: %v", err)
	}
	t.Setenv("SSHR_PIN_ASKPASS", "/bin/echo")
	if pin, err := fido2PIN("yubi"); err != nil || pin != "PIN of the security key yubi: " {
		t.Errorf("the PIN from SSHR_PIN_ASKPASS: %q %v", pin, err)
	}
	if err := pinFailure(errors.New("fido2-assert: fido_dev_get_assert: FIDO_ERR_PIN_INVALID")); !errors.Is(err, vault.ErrTokenPIN) {
		t.Errorf("a wrong PIN: %v", err)
	}
}
