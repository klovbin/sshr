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
	typ, err := makeSKKey(path, "c", false, false, run(map[string]string{"ed25519-sk": "Key enrollment failed: requested feature not supported"}))
	if err != nil || typ != "ecdsa-sk" || strings.Join(tried, ",") != "ed25519-sk,ecdsa-sk" {
		t.Fatalf("fallback: %q %v, tried %v", typ, err, tried)
	}
	tried = nil
	if _, err := makeSKKey(path, "c", false, false, run(map[string]string{"ed25519-sk": "Key enrollment failed: invalid PIN"})); err == nil || len(tried) != 1 {
		t.Fatalf("a wrong PIN went on to ECDSA: %v, tried %v", err, tried)
	}
	tried = nil
	if typ, err := makeSKKey(path, "c", true, false, run(nil)); err != nil || typ != "ed25519-sk" || len(tried) != 1 {
		t.Fatalf("plain run: %q %v, tried %v", typ, err, tried)
	}
}
