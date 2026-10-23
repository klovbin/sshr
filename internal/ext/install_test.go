package ext

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"sshr.dev/internal/app"
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

// gitStub puts a fake git first in PATH, a clone copies fixture into the last
// argument and adds a .git folder, rev-parse prints a fixed hash, every call
// is logged with the arguments and the environment
func gitStub(t *testing.T, fixture, body string) (log string) {
	t.Helper()
	bin := t.TempDir()
	log = filepath.Join(t.TempDir(), "log")
	stub := "#!/bin/sh\n" +
		"{ echo \"ARGS $*\"; env; } >> " + log + "\n" +
		"case \" $* \" in *\" clone \"*)\n" +
		body +
		"  for last; do :; done\n" +
		"  cp -r " + fixture + " \"$last\" && mkdir \"$last/.git\" && echo ref > \"$last/.git/HEAD\" ;;\n" +
		"*\" rev-parse \"*) echo 0123456789abcdef0123456789abcdef01234567 ;;\n" +
		"esac\n"
	os.WriteFile(filepath.Join(bin, "git"), []byte(stub), 0o700)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

func TestPrepareFromGitRecordsTheCommitAndDropsTheHistory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the git stub is a shell script")
	}
	t.Setenv("BW_SESSION", "secret")
	t.Setenv("OP_SESSION_acme", "secret")
	t.Setenv("GIT_SSH_COMMAND", "")
	os.Unsetenv("GIT_SSH_COMMAND")
	log := gitStub(t, source(t, "gitted", "#!/bin/sh\necho hi\n"), "")
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
	b, _ := os.ReadFile(log)
	got := string(b)
	for _, want := range []string{
		"clone --depth 1 --no-tags --single-branch --no-recurse-submodules --filter=blob:limit=5m --template= -- https://example.com/a/gitted.git",
		"protocol.allow=never", "protocol.https.allow=always", "protocol.ssh.allow=always",
		"core.hooksPath=" + os.DevNull, "filter.lfs.required=false",
		"GIT_ALLOW_PROTOCOL=https:ssh", "GIT_TERMINAL_PROMPT=0", "GIT_SSH_COMMAND=ssh -o BatchMode=yes",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("git was run without %q:\n%s", want, got)
		}
	}
	for _, secret := range []string{"BW_SESSION", "OP_SESSION_acme"} {
		if strings.Contains(got, secret) {
			t.Errorf("%s reached git", secret)
		}
	}
}

func TestACloneThatHangsIsStopped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the git stub is a shell script")
	}
	old := cloneTimeout
	cloneTimeout = 300 * time.Millisecond
	defer func() { cloneTimeout = old }()
	gitStub(t, source(t, "slow", "#!/bin/sh\n"), "  exec sleep 10\n")
	start := time.Now()
	_, err := Prepare("https://example.com/a/slow.git")
	if err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("the clone was not stopped at the limit")
	}
}

func TestAFolderDroppedInIsNotTrusted(t *testing.T) {
	r := &Registry{Root: t.TempDir()}
	dir := filepath.Join(r.Root, "dropped")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, ManifestFile), []byte(manifestOf("dropped")), 0o600)
	os.WriteFile(filepath.Join(dir, "run.sh"), []byte("#!/bin/sh\necho owned\n"), 0o700)
	// a lock that comes with the folder, with the right hash, as a dotfiles
	// checkout or a backup could carry it
	tree, _ := HashTree(dir)
	os.WriteFile(filepath.Join(dir, "sshr-ext.lock"), []byte(`{"source":"x","tree":"`+tree+`"}`), 0o600)
	if _, err := r.Find("dropped"); err == nil || !strings.Contains(err.Error(), "not installed by sshr ext install") {
		t.Fatalf("a folder with its own lock was trusted: %v", err)
	}
	if found, problems := r.List(); len(found) != 0 || len(problems) != 1 {
		t.Errorf("found %v, problems %v", found, problems)
	}
	if err := r.Remove("dropped"); err != nil {
		t.Errorf("a folder that was never installed cannot be removed: %v", err)
	}
}

func TestPinsFileMustBeAPlainFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	r := &Registry{Root: t.TempDir()}
	forged := filepath.Join(t.TempDir(), "forged.json")
	os.WriteFile(forged, []byte(`{"extensions":{}}`), 0o600)
	os.Symlink(forged, filepath.Join(r.Root, PinsFile))
	if _, err := r.Find("hello"); err == nil || !strings.Contains(err.Error(), "plain file") {
		t.Errorf("a linked pins file was read: %v", err)
	}
	os.Remove(filepath.Join(r.Root, PinsFile))
	os.WriteFile(filepath.Join(r.Root, PinsFile), []byte("not json"), 0o600)
	if _, err := r.Find("hello"); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Errorf("a damaged pins file: %v", err)
	}
}

func TestRemoveDropsThePin(t *testing.T) {
	r := &Registry{Root: t.TempDir()}
	st, err := Prepare(source(t, "hello", "#!/bin/sh\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Discard()
	if err := r.Install(st); err != nil {
		t.Fatal(err)
	}
	if err := r.Remove("hello"); err != nil {
		t.Fatal(err)
	}
	pins, err := r.pins()
	if err != nil || len(pins) != 0 {
		t.Errorf("pins after remove: %v, %v", pins, err)
	}
	// a folder put back by hand with the old files is not trusted again
	if err := os.MkdirAll(filepath.Join(r.Root, "hello"), 0o700); err == nil {
		os.WriteFile(filepath.Join(r.Root, "hello", ManifestFile), []byte(manifestOf("hello")), 0o600)
	}
	if _, err := r.Find("hello"); err == nil {
		t.Error("a removed extension came back without an install")
	}
}

func TestInstallsOfOneNameDoNotClobberEachOther(t *testing.T) {
	r := &Registry{Root: t.TempDir()}
	src := source(t, "busy", "#!/bin/sh\necho busy\n")
	errs := make(chan error, 6)
	for i := 0; i < 6; i++ {
		go func() {
			st, err := Prepare(src)
			if err != nil {
				errs <- err
				return
			}
			defer st.Discard()
			errs <- r.Install(st)
		}()
	}
	for i := 0; i < 6; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	inst, err := r.Find("busy")
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Verify(); err != nil {
		t.Errorf("after six installs at once: %v", err)
	}
	for _, left := range []string{".busy.new", ".busy.old"} {
		if _, err := os.Stat(filepath.Join(r.Root, left)); err == nil {
			t.Errorf("%s was left behind", left)
		}
	}
}

// .pins.json keeps the keys and the pin fields a newer sshr wrote, a pins
// file of a newer format is not written (#97)
func TestPinsKeepWhatANewerSshrWrote(t *testing.T) {
	reg := &Registry{Root: t.TempDir()}
	path := filepath.Join(reg.Root, PinsFile)
	os.WriteFile(path, []byte(`{"extensions":{"a":{"source":"s","tree":"t","signed_by":"k"}},"future":1}`), 0o600)
	if err := reg.Pin("b", Lock{Source: "s2", Tree: "t2"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	var file struct {
		Extensions map[string]map[string]any `json:"extensions"`
		Future     int                       `json:"future"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		t.Fatal(err)
	}
	if file.Future != 1 || file.Extensions["a"]["signed_by"] != "k" || file.Extensions["b"]["tree"] != "t2" {
		t.Fatalf("pins: %s", b)
	}
	os.WriteFile(path, []byte(`{"extensions":{},"version":3}`), 0o600)
	if err := reg.Pin("c", Lock{Source: "s", Tree: "t"}); !errors.Is(err, app.ErrNewerFormat) {
		t.Errorf("a newer pins file was written: %v", err)
	}
}

// a pins file of a newer format stops a removal and an install before any
// folder changes (#161)
func TestNewerPinsTouchNoFolder(t *testing.T) {
	r := &Registry{Root: t.TempDir()}
	st, err := Prepare(source(t, "hello", "#!/bin/sh\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Discard()
	if err := r.Install(st); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(r.Root, PinsFile)
	b, _ := os.ReadFile(path)
	var m map[string]any
	json.Unmarshal(b, &m)
	m["version"] = 3
	b, _ = json.Marshal(m)
	os.WriteFile(path, b, 0o600)
	if err := r.Remove("hello"); !errors.Is(err, app.ErrNewerFormat) {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(r.Root, "hello")); err != nil {
		t.Fatalf("the folder went: %v", err)
	}
	if err := r.Install(st); !errors.Is(err, app.ErrNewerFormat) {
		t.Fatalf("install: %v", err)
	}
}
