package folderstore

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"sshr.dev/internal/hosts"
	"sshr.dev/internal/syncclient"
	"sshr.dev/internal/vault"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func newStore(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := New(Config{Path: dir})
	must(t, err)
	return s
}

const (
	blob     = "blobs/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	manifest = "manifests/00000000000000000001"
)

func TestStoreObjects(t *testing.T) {
	s := newStore(t, t.TempDir())
	if _, err := s.Get(manifest, 10); err != syncclient.ErrNotFound {
		t.Fatalf("missing = %v", err)
	}
	must(t, s.Create(manifest, []byte("one")))
	if err := s.Create(manifest, []byte("two")); err != syncclient.ErrExists {
		t.Fatalf("second create = %v", err)
	}
	if b, err := s.Get(manifest, 10); err != nil || string(b) != "one" {
		t.Fatalf("get %q %v", b, err)
	}
	if _, err := s.Get(manifest, 2); err != syncclient.ErrTooLarge {
		t.Fatalf("too large = %v", err)
	}
	must(t, s.Put(blob, []byte("b")))
	must(t, s.Put(blob, []byte("c")))
	names, err := s.List("blobs/")
	if err != nil || len(names) != 1 || names[0] != blob {
		t.Fatalf("list %v %v", names, err)
	}
	must(t, s.Delete(blob))
	must(t, s.Delete(blob))
	if err := syncclient.ProbeCreate(s); err != nil {
		t.Errorf("the probe of create: %v", err)
	}
	for _, bad := range []string{"../x", "blobs/../../x", "account2", "BLOBS/aa", "manifests/1"} {
		if err := s.Put(bad, nil); err == nil {
			t.Errorf("%q was taken", bad)
		}
	}
}

// a link planted by another device leads nowhere outside the folder, junk
// is not listed
func TestHostileFolder(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	s := newStore(t, dir)
	if runtime.GOOS != "windows" {
		must(t, os.Symlink(outside, filepath.Join(dir, "blobs")))
		if err := s.Put(blob, []byte("x")); err == nil {
			t.Error("a write went through a link out of the folder")
		}
		if left, _ := os.ReadDir(outside); len(left) != 0 {
			t.Errorf("files outside the folder: %v", left)
		}
		os.Remove(filepath.Join(dir, "blobs"))
		must(t, os.Mkdir(filepath.Join(dir, "blobs"), 0o700))
		must(t, os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, filepath.FromSlash(blob))))
		os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0o600)
		if b, err := s.Get(blob, 100); err == nil {
			t.Errorf("a link to a file outside was read: %q", b)
		}
	}
	must(t, os.MkdirAll(filepath.Join(dir, "manifests"), 0o700))
	for i := 0; i < 50; i++ {
		os.WriteFile(filepath.Join(dir, "manifests", fmt.Sprintf("junk-%d", i)), nil, 0o600)
	}
	if names, err := s.List("manifests/"); err != nil || len(names) != 0 {
		t.Errorf("junk listed: %v %v", names, err)
	}
}

// a change iCloud moved off the machine is said to be so, not missing,
// the history would look shorter than it is
func TestICloudPlaceholder(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir)
	must(t, os.MkdirAll(filepath.Join(dir, "manifests"), 0o700))
	must(t, os.WriteFile(filepath.Join(dir, "manifests", ".00000000000000000001.icloud"), nil, 0o600))
	if _, err := s.List("manifests/"); err == nil || !strings.Contains(err.Error(), "not downloaded") {
		t.Errorf("list with a placeholder: %v", err)
	}
	if _, err := s.Get(manifest, 10); err == nil || errors.Is(err, syncclient.ErrNotFound) {
		t.Errorf("get of a placeholder: %v", err)
	}
}

// memKeychain keeps secrets in memory, the test never reaches the system
// keychain
type memKeychain struct {
	mu sync.Mutex
	m  map[string]string
}

func (k *memKeychain) Get(n string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.m[n]
	if !ok {
		return "", vault.ErrSecretNotFound
	}
	return v, nil
}
func (k *memKeychain) Set(n, v string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.m[n] = v
	return nil
}
func (k *memKeychain) Delete(n string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.m, n)
	return nil
}

// two devices with a store each on one folder pair and sync, a conflict
// copy of a change stops them until it is gone
func TestSyncThroughFolder(t *testing.T) {
	vault.SetKeychain(&memKeychain{m: map[string]string{}})
	vault.ResetForTest(filepath.Join(t.TempDir(), ".lock"))
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	dir := t.TempDir()
	mk := func(p string) *syncclient.Client {
		return &syncclient.Client{Store: &hosts.Store{Dir: t.TempDir()}, Dir: t.TempDir(), KeyPrefix: p,
			Backend: syncclient.ObjectBackend{Store: newStore(t, dir)}, Log: io.Discard}
	}
	a, b := mk("a-"), mk("b-")
	_, err := a.Store.Add(hosts.Host{Name: "web", Host: "10.0.0.1", User: "u"})
	must(t, err)
	must(t, a.Init("folder", "laptop"))
	code, err := a.Invite()
	must(t, err)
	_, err = b.Join("folder", code, "desktop")
	must(t, err)
	pending, err := a.Pending()
	must(t, err)
	_, err = a.Approve(pending[0].ID)
	must(t, err)
	must(t, b.Pull())
	if got, _ := b.Store.List(); len(got) != 1 || got[0].Name != "web" {
		t.Fatalf("hosts on b %+v", got)
	}

	// Syncthing kept one change and made a copy of the other
	copyName := filepath.Join(dir, "manifests", "00000000000000000002.sync-conflict-20261025-120000-ABCDEFG")
	must(t, os.WriteFile(copyName, []byte("{}"), 0o600))
	if err := b.Pull(); !errors.Is(err, syncclient.ErrFork) || !strings.Contains(err.Error(), "sync-conflict") {
		t.Fatalf("pull with a conflict copy: %v", err)
	}
	os.Remove(copyName)
	must(t, b.Pull())
}

// two processes that create the same names in one folder, exactly one of
// them gets each name
func TestCreateRaceBetweenProcesses(t *testing.T) {
	if dir := os.Getenv("SSHR_FOLDER_RACE"); dir != "" {
		s, err := New(Config{Path: dir})
		if err != nil {
			os.Exit(2)
		}
		won := 0
		for i := 0; i < 100; i++ {
			name := fmt.Sprintf("manifests/%020d", i+1)
			if s.Create(name, []byte(os.Getenv("SSHR_FOLDER_WHO"))) == nil {
				won++
			}
		}
		fmt.Print(won)
		os.Exit(0)
	}
	dir := t.TempDir()
	run := func(who string) *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=TestCreateRaceBetweenProcesses")
		cmd.Env = append(os.Environ(), "SSHR_FOLDER_RACE="+dir, "SSHR_FOLDER_WHO="+who)
		return cmd
	}
	ca, cb := run("a"), run("b")
	var outA, outB strings.Builder
	ca.Stdout, cb.Stdout = &outA, &outB
	must(t, ca.Start())
	must(t, cb.Start())
	must(t, ca.Wait())
	must(t, cb.Wait())
	wa, _ := strconv.Atoi(outA.String())
	wb, _ := strconv.Atoi(outB.String())
	if wa+wb != 100 {
		t.Fatalf("a won %d and b won %d of 100 names", wa, wb)
	}
	s := newStore(t, dir)
	for i := 0; i < 100; i++ {
		b, err := s.Get(fmt.Sprintf("manifests/%020d", i+1), 10)
		if err != nil || (string(b) != "a" && string(b) != "b") {
			t.Fatalf("name %d holds %q %v", i+1, b, err)
		}
	}
}

// files a sync tool or a person leaves are no conflict, a copy of a change
// or of the account is, the archive of Syncthing and folders an account
// does not have are not walked, an old temporary file is swept
func TestConflictsAndJunk(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir)
	for _, f := range []string{".stversions/account~20261025", ".stversions/manifests/00000000000000000001~1", "manifests/Thumbs.db", "manifests/desktop.ini", "other/account copy", "blobs/accountfoo"} {
		must(t, os.MkdirAll(filepath.Join(dir, filepath.Dir(f)), 0o700))
		must(t, os.WriteFile(filepath.Join(dir, filepath.FromSlash(f)), nil, 0o600))
	}
	if c, err := s.Conflicts(); err != nil || len(c) != 0 {
		t.Fatalf("junk taken for conflicts: %q %v", c, err)
	}
	for _, f := range []string{"manifests/00000000000000000002.sync-conflict-20261025-120000-ABCDEFG", "account (conflicted copy 2026-10-25)", "manifests/00000000000000000003 2"} {
		must(t, os.WriteFile(filepath.Join(dir, filepath.FromSlash(f)), nil, 0o600))
	}
	if c, err := s.Conflicts(); err != nil || len(c) != 3 {
		t.Fatalf("conflict copies: %q %v", c, err)
	}
	old := filepath.Join(dir, "blobs", ".sshr-0011223344556677.tmp")
	must(t, os.WriteFile(old, nil, 0o600))
	must(t, os.Chtimes(old, time.Now().Add(-2*time.Hour), time.Now().Add(-2*time.Hour)))
	must(t, s.Put(blob, []byte("x")))
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("an old temporary file stayed: %v", err)
	}
}
