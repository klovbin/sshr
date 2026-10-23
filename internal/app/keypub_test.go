package app

import (
	"path/filepath"
	"testing"
)

// the public half of a key in 1Password or Bitwarden is read by running op
// or bw, a missing program is an error and not a silent empty key (#98)
func TestFillKeyPubRunsTheManager(t *testing.T) {
	oldOP, oldBW := opBin, bwBin
	opBin, bwBin = filepath.Join(t.TempDir(), "no-op"), filepath.Join(t.TempDir(), "no-bw")
	t.Cleanup(func() { opBin, bwBin = oldOP, oldBW })
	for _, h := range []Host{
		{Name: "a", Host: "h", User: "u", KeyMode: KeyOnePassword, KeyRef: "op://v/item/private key"},
		{Name: "b", Host: "h", User: "u", KeyMode: KeyBitwarden, KeyRef: "0123456789abcdef0123456789abcdef"},
	} {
		if err := fillKeyPub(&h); err == nil {
			t.Errorf("%s: fillKeyPub ran nothing", h.Name)
		}
	}
}
