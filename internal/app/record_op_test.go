//go:build !windows

package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// an edit of a host of a newer format is refused before a 1Password item
// is made for it (#165)
func TestNewerHostMakesNoOnePasswordItem(t *testing.T) {
	op := fakeOP(t)
	useMockKeychain(t)
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Name: "web", Host: "10.0.0.5", User: "u", PasswordMode: PasswordAsk})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.Dir, h.ID+".json")
	b, _ := os.ReadFile(path)
	var m map[string]any
	json.Unmarshal(b, &m)
	m["version"] = 2
	b, _ = json.Marshal(m)
	os.WriteFile(path, b, 0o600)
	_, err = s.Update(h.ID, Host{Name: "web", Host: "10.0.0.5", User: "u", PasswordMode: PasswordOnePassword, Password: "pw"})
	if !errors.Is(err, ErrNewerFormat) {
		t.Fatalf("update: %v", err)
	}
	if _, err := os.Stat(filepath.Join(op, "create.json")); err == nil {
		t.Error("a 1Password item was made for a host that is not written")
	}
}
