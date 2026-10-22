package ext

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEnvDropsSecretsAndAddsTheProtocol(t *testing.T) {
	parent := []string{
		"PATH=/bin", "HOME=/home/u", "LANG=C",
		"SSH_ASKPASS=/x", "ssh_askpass_require=force", "SSH_AUTH_SOCK=/agent",
		"BW_SESSION=s", "OP_SESSION_my=s", "OP_SERVICE_ACCOUNT_TOKEN=t",
		"SSHR_ASKPASS_TOKEN=t", "SSHR_SYNC_KEYS=k",
	}
	got := strings.Join(Env(parent, KindCommand, "/ext/dir", "/usr/bin/sshr"), "\n")
	for _, bad := range []string{"SSH_ASKPASS", "ssh_askpass_require", "BW_SESSION", "OP_SESSION_my", "OP_SERVICE_ACCOUNT_TOKEN", "SSHR_ASKPASS_TOKEN", "SSHR_SYNC_KEYS"} {
		if strings.Contains(got, bad) {
			t.Errorf("%s reaches the extension", bad)
		}
	}
	for _, want := range []string{"PATH=/bin", "HOME=/home/u", "LANG=C", "SSH_AUTH_SOCK=/agent",
		"SSHR_EXT_PROTOCOL=1", "SSHR_EXT_KIND=command", "SSHR_EXT_DIR=/ext/dir", "SSHR_BIN=/usr/bin/sshr"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s is missing from the environment", want)
		}
	}
}

func TestCommandRunsTheInstalledProgram(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the extension is a shell script")
	}
	t.Setenv("BW_SESSION", "secret")
	t.Setenv("SSH_ASKPASS", "/some/askpass")
	r := &Registry{Root: t.TempDir()}
	install(t, r, "hello", map[string]string{
		ManifestFile: strings.Replace(manifestOf("hello"), `["./run.sh"]`, `["./run.sh","fixed"]`, 1),
		"run.sh":     "#!/bin/sh\necho \"args=$*\"\necho \"kind=$SSHR_EXT_KIND\"\necho \"bw=${BW_SESSION:-none} askpass=${SSH_ASKPASS:-none}\"\nexit 3\n",
	})
	inst, err := r.Find("hello")
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := inst.Command(KindCommand, []string{"a", "b c"}, "/usr/bin/sshr")
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.Output()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 3 {
		t.Fatalf("err = %v, want exit code 3 passed through", err)
	}
	got := string(out)
	for _, want := range []string{"args=fixed a b c", "kind=command", "bw=none askpass=none"} {
		if !strings.Contains(got, want) {
			t.Errorf("output %q misses %q", got, want)
		}
	}
}

func TestCommandRefusesWhatWasNotInstalled(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the extension is a shell script")
	}
	r := &Registry{Root: t.TempDir()}
	dir := install(t, r, "hello", map[string]string{ManifestFile: manifestOf("hello"), "run.sh": "#!/bin/sh\necho hi\n"})
	inst, _ := r.Find("hello")
	if _, err := inst.Command(KindImport, nil, "sshr"); err == nil || !strings.Contains(err.Error(), "does not do") {
		t.Errorf("a kind the extension does not have: %v", err)
	}
	os.WriteFile(filepath.Join(dir, "run.sh"), []byte("#!/bin/sh\nrm -rf ~\n"), 0o700)
	if _, err := inst.Command(KindCommand, nil, "sshr"); !errors.Is(err, ErrChanged) {
		t.Errorf("a program changed after install ran: %v", err)
	}
}

func TestCommandRefusesAProgramThatIsNotExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no executable bit")
	}
	r := &Registry{Root: t.TempDir()}
	install(t, r, "hello", map[string]string{ManifestFile: manifestOf("hello"), "run.sh": "#!/bin/sh\n"})
	dir := filepath.Join(r.Root, "hello")
	os.Chmod(filepath.Join(dir, "run.sh"), 0o600)
	tree, _ := HashTree(dir)
	WriteLock(dir, Lock{Source: "test", Tree: tree})
	inst, _ := r.Find("hello")
	if _, err := inst.Command(KindCommand, nil, "sshr"); err == nil || !strings.Contains(err.Error(), "not executable") {
		t.Errorf("err = %v", err)
	}
}
