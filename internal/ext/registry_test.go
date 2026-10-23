package ext

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// install makes an extension folder the way sshr ext install will: files,
// then a lock with the hash of them
func install(t *testing.T, r *Registry, name string, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(r.Root, name)
	for rel, body := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o600)
		if strings.HasSuffix(rel, ".sh") {
			mode = 0o700
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	tree, err := HashTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteLock(dir, Lock{Source: "test", Tree: tree}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func manifestOf(name string) string {
	return `{"protocol":1,"name":"` + name + `","version":"1","description":"d","command":{"default":["./run.sh"]},"kinds":["command"]}`
}

func TestRegistryFindsAndVerifies(t *testing.T) {
	r := &Registry{Root: t.TempDir()}
	dir := install(t, r, "hello", map[string]string{ManifestFile: manifestOf("hello"), "run.sh": "echo hi\n"})
	inst, err := r.Find("hello")
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Verify(); err != nil {
		t.Fatalf("fresh install: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run.sh"), []byte("echo changed\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := inst.Verify(); !errors.Is(err, ErrChanged) {
		t.Fatalf("changed program: err = %v, want ErrChanged", err)
	}
}

func TestVerifySeesAnAddedFileAndAChangedManifest(t *testing.T) {
	r := &Registry{Root: t.TempDir()}
	dir := install(t, r, "hello", map[string]string{ManifestFile: manifestOf("hello"), "run.sh": "echo hi\n"})
	inst, _ := r.Find("hello")
	os.WriteFile(filepath.Join(dir, "extra.py"), []byte("x"), 0o600)
	if err := inst.Verify(); !errors.Is(err, ErrChanged) {
		t.Errorf("an added file: err = %v", err)
	}
	os.Remove(filepath.Join(dir, "extra.py"))
	if err := inst.Verify(); err != nil {
		t.Fatalf("after removing it again: %v", err)
	}
	os.WriteFile(filepath.Join(dir, ManifestFile), []byte(strings.Replace(manifestOf("hello"), `"version":"1"`, `"version":"2"`, 1)), 0o600)
	if err := inst.Verify(); !errors.Is(err, ErrChanged) {
		t.Errorf("a changed manifest: err = %v", err)
	}
}

func TestHashTreeSeesTheExecutableBit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no executable bit")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "run")
	os.WriteFile(p, []byte("x"), 0o600)
	a, _ := HashTree(dir)
	os.Chmod(p, 0o700)
	b, _ := HashTree(dir)
	if a == b {
		t.Error("making a file executable did not change the hash")
	}
}

func TestHashTreeIgnoresTheLockButSeesGitAndLinks(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a"), []byte("x"), 0o600)
	base, err := HashTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, LockFile), []byte("{}"), 0o600)
	if got, _ := HashTree(dir); got != base {
		t.Error("the lock file changes the hash")
	}
	os.MkdirAll(filepath.Join(dir, "lib", ".git"), 0o700)
	os.WriteFile(filepath.Join(dir, "lib", ".git", "payload"), []byte("x"), 0o700)
	if got, _ := HashTree(dir); got == base {
		t.Error("a file added under .git did not change the hash")
	}
	if runtime.GOOS == "windows" {
		return
	}
	if err := os.Symlink("/etc/hostname", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := HashTree(dir); err == nil {
		t.Error("a link inside an extension was hashed")
	}
}

func TestHashTreeCountsFolders(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i <= treeMaxFiles; i++ {
		os.Mkdir(filepath.Join(dir, "d"+strconv.Itoa(i)), 0o700)
	}
	if _, err := HashTree(dir); err == nil {
		t.Error("more empty folders than the limit were hashed")
	}
}

func TestFindRefusesNamesThatLeaveTheFolder(t *testing.T) {
	r := &Registry{Root: filepath.Join(t.TempDir(), "extensions")}
	for _, name := range []string{"..", "../x", "a/b", "", ".hidden", "UP"} {
		if _, err := r.Find(name); !errors.Is(err, ErrNotInstalled) {
			t.Errorf("Find(%q) = %v, want ErrNotInstalled", name, err)
		}
		if err := r.Remove(name); !errors.Is(err, ErrNotInstalled) {
			t.Errorf("Remove(%q) = %v, want ErrNotInstalled", name, err)
		}
	}
}

func TestListKeepsGoodOnesNextToBrokenOnes(t *testing.T) {
	r := &Registry{Root: t.TempDir()}
	install(t, r, "good", map[string]string{ManifestFile: manifestOf("good"), "run.sh": "x"})
	install(t, r, "named-wrong", map[string]string{ManifestFile: manifestOf("other"), "run.sh": "x"})
	os.MkdirAll(filepath.Join(r.Root, "nolock"), 0o700)
	os.WriteFile(filepath.Join(r.Root, "nolock", ManifestFile), []byte(manifestOf("nolock")), 0o600)
	os.WriteFile(filepath.Join(r.Root, "stray-file"), []byte("x"), 0o600)
	found, problems := r.List()
	if len(found) != 1 || found[0].Name != "good" {
		t.Fatalf("found %v", found)
	}
	if len(problems) != 3 {
		t.Fatalf("problems = %v, want the wrong name, the missing lock and the stray file", problems)
	}
}

func TestListOfNoFolderIsEmpty(t *testing.T) {
	r := &Registry{Root: filepath.Join(t.TempDir(), "nope")}
	if found, problems := r.List(); len(found) != 0 || len(problems) != 0 {
		t.Errorf("found %v problems %v", found, problems)
	}
}

func TestRemoveDeletesTheFolderNotWhatALinkPointsTo(t *testing.T) {
	r := &Registry{Root: t.TempDir()}
	install(t, r, "hello", map[string]string{ManifestFile: manifestOf("hello"), "run.sh": "x"})
	if err := r.Remove("hello"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Find("hello"); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("still installed: %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "keep"), []byte("x"), 0o600)
	if err := os.Symlink(outside, filepath.Join(r.Root, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := r.Remove("linked"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outside, "keep")); err != nil {
		t.Errorf("Remove followed a link and deleted what it points to: %v", err)
	}
}
