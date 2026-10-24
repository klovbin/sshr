package main

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

// sshr key new --sk tries Ed25519 first and ECDSA when the token makes no
// Ed25519 keys, any other failure (a wrong PIN, no token) stops at once
func TestMakeSKKeyFallsBackToECDSA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sk")
	var tried []string
	run := func(answer map[string]string) func([]string, io.Writer) error {
		return func(args []string, w io.Writer) error {
			typ := args[1]
			tried = append(tried, typ)
			if msg, ok := answer[typ]; ok {
				fmt.Fprintln(w, msg)
				return errors.New("exit status 1")
			}
			return nil
		}
	}
	typ, err := makeSKKey(path, "c", false, false, false, run(map[string]string{"ed25519-sk": "Key enrollment failed: requested feature not supported"}))
	if err != nil || typ != "ecdsa-sk" || strings.Join(tried, ",") != "ed25519-sk,ecdsa-sk" {
		t.Fatalf("fallback: %q %v, tried %v", typ, err, tried)
	}
	tried = nil
	if _, err := makeSKKey(path, "c", false, false, false, run(map[string]string{"ed25519-sk": "Key enrollment failed: invalid PIN"})); err == nil || len(tried) != 1 {
		t.Fatalf("a wrong PIN went on to ECDSA: %v, tried %v", err, tried)
	}
	// with --resident or --verify-required the same answer means the token
	// lacks the option, ECDSA would fail the same way (#339)
	for _, opt := range [][2]bool{{true, false}, {false, true}} {
		tried = nil
		_, err := makeSKKey(path, "c", opt[0], opt[1], false, run(map[string]string{"ed25519-sk": "Key enrollment failed: requested feature not supported"}))
		if err == nil || len(tried) != 1 || !strings.Contains(err.Error(), "--resident or --verify-required") {
			t.Fatalf("options %v: %v, tried %v", opt, err, tried)
		}
	}
	tried = nil
	if typ, err := makeSKKey(path, "c", true, false, false, run(nil)); err != nil || typ != "ed25519-sk" || len(tried) != 1 {
		t.Fatalf("plain run: %q %v, tried %v", typ, err, tried)
	}
}

// --no-passphrase reaches ssh-keygen with --sk too (#340)
func TestMakeSKKeyNoPassphrase(t *testing.T) {
	var got []string
	run := func(args []string, w io.Writer) error { got = args; return nil }
	if _, err := makeSKKey(filepath.Join(t.TempDir(), "sk"), "c", false, false, true, run); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(got, " "), "-N ") {
		t.Errorf("args %q", got)
	}
}
