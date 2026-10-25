package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshr.dev/internal/hosts"
	"sshr.dev/internal/sshconf"
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

// the host store inside the ssh and ssh config environments carries the
// hooks of Store too, ImportSSHConfig adds its hosts through it, so an
// imported host refreshes an installed export (#222), ImportSSHConfig
// through Store is tested below with the config of the test
func TestEnvHostStoresKeepTheHooks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	out := filepath.Join(home, "ssh_config")
	os.WriteFile(out, []byte("# Written by sshr, edits here are lost, change the hosts in sshr\n\n"), 0o600)
	s := &Store{Dir: t.TempDir(), SSHConfigOut: out}
	if _, err := s.confEnv().Hosts.Add(Host{Name: "from-conf-env", Host: "10.0.0.2", User: "u"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.env().Hosts.Add(Host{Name: "from-ssh-env", Host: "10.0.0.3", User: "u"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	for _, name := range []string{"from-conf-env", "from-ssh-env"} {
		if !strings.Contains(string(b), name) {
			t.Errorf("the export was not rewritten after a host added through the env of %s:\n%s", name, b)
		}
	}
	// a Store inside Locked hands the held store to the env, no second lock
	err := s.Locked(func(tx *Store) error {
		if tx.env().Hosts != tx.db() || tx.confEnv().Hosts != tx.db() {
			t.Error("the env of a held Store is not its held host store")
		}
		_, err := tx.confEnv().Hosts.Add(Host{Name: "inside-lock", Host: "10.0.0.4", User: "u"})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// a removed host leaves the hardware key list (#357)
func TestDeleteReleasesTheHardwareKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Name: "web", Host: "10.0.0.1", User: "u"})
	if err != nil {
		t.Fatal(err)
	}
	st, _ := LoadSettings()
	st.RequireHardwareKey(h.ID)
	st.RequireHardwareKey("other")
	SaveSettings(st)
	if err := s.Delete(h.ID); err != nil {
		t.Fatal(err)
	}
	st, _ = LoadSettings()
	if st.HardwareKeyRequired(h.ID) || !st.HardwareKeyRequired("other") {
		t.Fatalf("hardware_key_hosts after the delete: %v", st.HardwareKeyHosts)
	}
}

// a host of an ssh config comes into the store through Store with its
// address, user and port, the config is the one of the test, never the
// user's own
func TestImportSSHConfigThroughStore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	conf := filepath.Join(home, "ssh_config")
	os.WriteFile(conf, []byte("Host web-import\n  HostName 10.0.0.9\n  User deploy\n  Port 2222\n"), 0o600)
	old := sshconf.SetConfigFileForTest(conf)
	t.Cleanup(func() { sshconf.SetConfigFileForTest(old) })
	s := &Store{Dir: t.TempDir()}
	items, err := s.ImportSSHConfig(false)
	if err != nil {
		t.Skipf("ssh -G is not usable here: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("imported %+v", items)
	}
	h, err := s.Find("web-import")
	if err != nil || h.Host != "10.0.0.9" || h.User != "deploy" || h.Port != 2222 {
		t.Fatalf("host %+v %v", h, err)
	}
}
