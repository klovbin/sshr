package ext

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// source makes a folder with an extension in it
func source(t *testing.T, name, script string) string {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ManifestFile), []byte(manifestOf(name)), 0o600)
	os.WriteFile(filepath.Join(dir, "run.sh"), []byte(script), 0o700)
	return dir
}

func TestPrepareAFolderAndInstallIt(t *testing.T) {
	src := source(t, "hello", "#!/bin/sh\necho hi\n")
	os.MkdirAll(filepath.Join(src, ".git"), 0o700)
	os.WriteFile(filepath.Join(src, ".git", "HEAD"), []byte("ref"), 0o600)
	st, err := Prepare(src)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Discard()
	if st.Name != "hello" || st.Files != 2 || st.Lock.Source != src || st.Lock.Commit != "" || st.Lock.Tree == "" {
		t.Fatalf("staged %+v, files %d", st.Lock, st.Files)
	}
	if _, err := os.Stat(filepath.Join(st.files, ".git")); err == nil {
		t.Error(".git was copied")
	}
	r := &Registry{Root: filepath.Join(t.TempDir(), "extensions")}
	if err := r.Install(st); err != nil {
		t.Fatal(err)
	}
	inst, err := r.Find("hello")
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Verify(); err != nil {
		t.Fatalf("a fresh install does not verify: %v", err)
	}
	if inst.Lock.Tree != st.Lock.Tree {
		t.Error("the lock holds another hash than the one shown to the user")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(inst.Dir, "run.sh"))
		if err != nil || info.Mode()&0o100 == 0 {
			t.Errorf("the program lost its executable bit: %v", err)
		}
	}
}

func TestInstallingAgainTrustsTheChangedFiles(t *testing.T) {
	r := &Registry{Root: t.TempDir()}
	src := source(t, "hello", "#!/bin/sh\necho one\n")
	st, err := Prepare(src)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Discard()
	if err := r.Install(st); err != nil {
		t.Fatal(err)
	}
	inst, _ := r.Find("hello")
	os.WriteFile(filepath.Join(inst.Dir, "run.sh"), []byte("#!/bin/sh\necho edited\n"), 0o700)
	if err := inst.Verify(); !errors.Is(err, ErrChanged) {
		t.Fatalf("a hand edit passed: %v", err)
	}
	os.WriteFile(filepath.Join(src, "run.sh"), []byte("#!/bin/sh\necho two\n"), 0o700)
	st2, err := Prepare(src)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Discard()
	if err := r.Install(st2); err != nil {
		t.Fatal(err)
	}
	inst, _ = r.Find("hello")
	if err := inst.Verify(); err != nil {
		t.Fatalf("after installing again: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(inst.Dir, "run.sh")); !strings.Contains(string(b), "two") {
		t.Errorf("the new files were not installed: %q", b)
	}
	for _, left := range []string{".hello.new", ".hello.old"} {
		if _, err := os.Stat(filepath.Join(r.Root, left)); err == nil {
			t.Errorf("%s was left behind", left)
		}
	}
}

func TestPrepareRefusesWhatCannotBePinned(t *testing.T) {
	if runtime.GOOS != "windows" {
		src := source(t, "hello", "#!/bin/sh\n")
		os.Symlink("/etc/hostname", filepath.Join(src, "link"))
		if _, err := Prepare(src); err == nil || !strings.Contains(err.Error(), "not a plain file") {
			t.Errorf("a link in the extension: %v", err)
		}
	}
	empty := t.TempDir()
	if _, err := Prepare(empty); err == nil || !strings.Contains(err.Error(), ManifestFile) {
		t.Errorf("a folder without a manifest: %v", err)
	}
	bad := t.TempDir()
	os.WriteFile(filepath.Join(bad, ManifestFile), []byte(`{"protocol":1,"name":"../x"}`), 0o600)
	if _, err := Prepare(bad); err == nil {
		t.Error("a bad manifest was accepted")
	}
	for _, s := range []string{"-x", "file:///etc", "ext::sh -c id", "/no/such/folder", "http://example.com/x.git"} {
		if _, err := Prepare(s); err == nil {
			t.Errorf("Prepare(%q) was accepted", s)
		}
	}
}

func TestPrepareLeavesACarriedLockBehind(t *testing.T) {
	src := source(t, "hello", "#!/bin/sh\n")
	os.WriteFile(filepath.Join(src, LockFile), []byte(`{"tree":"forged"}`), 0o600)
	st, err := Prepare(src)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Discard()
	if _, err := os.Stat(filepath.Join(st.files, LockFile)); err == nil {
		t.Error("a lock that came with the extension was copied")
	}
}

func TestIsGitURL(t *testing.T) {
	for in, want := range map[string]bool{
		"https://github.com/a/b.git": true, "ssh://git@host/a/b": true, "git@github.com:a/b.git": true,
		"file:///tmp/x": false, "ext::sh -c id": false, "./local": false, "/abs/path": false,
		"http://host/x.git": false, "-oProxyCommand=x": false, "C:\\x\\y": false,
	} {
		if got := isGitURL(in); got != want {
			t.Errorf("isGitURL(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestPrepareFromGitRecordsTheCommitAndDropsTheHistory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the git stub is a shell script")
	}
	fixture := source(t, "gitted", "#!/bin/sh\necho hi\n")
	bin := t.TempDir()
	envLog := filepath.Join(t.TempDir(), "env")
	stub := "#!/bin/sh\n" +
		"if [ \"$1\" = clone ]; then\n" +
		"  for last; do :; done\n" +
		"  echo \"$GIT_ALLOW_PROTOCOL $GIT_TERMINAL_PROMPT $*\" > " + envLog + "\n" +
		"  cp -r " + fixture + " \"$last\" && mkdir \"$last/.git\" && echo ref > \"$last/.git/HEAD\"\n" +
		"elif [ \"$3\" = rev-parse ]; then echo 0123456789abcdef0123456789abcdef01234567; fi\n"
	os.WriteFile(filepath.Join(bin, "git"), []byte(stub), 0o700)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	st, err := Prepare("https://example.com/a/gitted.git")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Discard()
	if st.Lock.Commit != "0123456789abcdef0123456789abcdef01234567" || st.Name != "gitted" {
		t.Fatalf("lock %+v, name %s", st.Lock, st.Name)
	}
	if _, err := os.Stat(filepath.Join(st.files, ".git")); err == nil {
		t.Error("the git history was kept")
	}
	got, _ := os.ReadFile(envLog)
	for _, want := range []string{"https:ssh 0 clone --depth 1", "-- https://example.com/a/gitted.git"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("git was run as %q, missing %q", got, want)
		}
	}
}
