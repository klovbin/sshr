package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshr.dev/internal/hosts"
)

// the host store the sync client gets carries the hooks of Store, a host
// imported under its lock rewrites an installed ssh config export (#103)
func TestHostsKeepsTheExportHook(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	out := filepath.Join(home, "ssh_config")
	// the first line of an export sshr wrote, see sshconf
	os.WriteFile(out, []byte("# Written by sshr, edits here are lost, change the hosts in sshr\n\n"), 0o600)
	s := &Store{Dir: t.TempDir(), SSHConfigOut: out}
	err := s.Hosts().Locked(func(tx *hosts.Store) error {
		_, err := tx.Import(Host{ID: "0123456789abcdef0123456789abcdef", Name: "synced-web", Host: "10.0.0.1", User: "u"})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	if !strings.Contains(string(b), "synced-web") {
		t.Fatalf("the export was not rewritten after a sync import:\n%s", b)
	}
}
