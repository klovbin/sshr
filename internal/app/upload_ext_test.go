package app

import (
	"strings"
	"testing"
)

// the file extension of an upload goes into the script on the server (#41)
func TestUploadRefusesShellInExtension(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	h := &Host{ID: "x", Name: "x", Host: "127.0.0.1", User: "u", Port: 1, PasswordMode: PasswordAsk}
	for _, bad := range []string{"$(id)", "png;id", "a b", "`id`", "toolongextension"} {
		if _, err := s.UploadImage(h, []byte("x"), bad, true); err == nil || !strings.Contains(err.Error(), "extension") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}
