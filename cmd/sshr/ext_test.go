package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"sshr.dev/internal/ext"
)

// TestMain lets a test run the CLI as a child process, the test binary
// behaves as sshr when SSHR_TEST_CLI is set
func TestMain(m *testing.M) {
	if os.Getenv("SSHR_TEST_CLI") == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

// sshrIn runs the CLI with a home folder of its own and returns what it
// printed and its exit code
func sshrIn(t *testing.T, home string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "SSHR_TEST_CLI=1", "HOME="+home, "USERPROFILE="+home, "XDG_CONFIG_HOME="+filepath.Join(home, ".config"))
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	code := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return out.String(), errOut.String(), code
}

// installExt puts an extension into the home folder the way an install does
func installExt(t *testing.T, home, name, script string) string {
	t.Helper()
	dir := filepath.Join(home, ".sshr", "extensions", name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := `{"protocol":1,"name":"` + name + `","version":"1","description":"test","command":{"default":["./run.sh"]},"kinds":["command"]}`
	os.WriteFile(filepath.Join(dir, ext.ManifestFile), []byte(manifest), 0o600)
	os.WriteFile(filepath.Join(dir, "run.sh"), []byte(script), 0o700)
	tree, err := ext.HashTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	reg := &ext.Registry{Root: filepath.Join(home, ".sshr", "extensions")}
	if err := reg.Pin(name, ext.Lock{Source: "test", Tree: tree}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestExtensionRunsByNameWithItsExitCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the extension is a shell script")
	}
	home := t.TempDir()
	installExt(t, home, "hello", "#!/bin/sh\necho \"hello $*\"\necho \"from=$SSHR_EXT_KIND\"\nexit 7\n")
	out, _, code := sshrIn(t, home, "hello", "a", "b")
	if code != 7 || !strings.Contains(out, "hello a b") || !strings.Contains(out, "from=command") {
		t.Fatalf("code %d, output %q", code, out)
	}
}

func TestBuiltinCommandsBeatExtensions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the extension is a shell script")
	}
	home := t.TempDir()
	for _, name := range []string{"list", "ext", "connect"} {
		installExt(t, home, name, "#!/bin/sh\necho EXTENSION-RAN\nexit 9\n")
	}
	for _, args := range [][]string{{"list"}, {"ext", "list"}} {
		out, _, code := sshrIn(t, home, args...)
		if strings.Contains(out, "EXTENSION-RAN") || code == 9 {
			t.Errorf("sshr %v ran the extension, code %d, output %q", args, code, out)
		}
	}
}

func TestUnknownWordStillGetsTheHint(t *testing.T) {
	_, errOut, code := sshrIn(t, t.TempDir(), "lsit")
	if code != 1 || !strings.Contains(errOut, `unknown command "lsit"`) || !strings.Contains(errOut, "did you mean") {
		t.Fatalf("code %d, stderr %q", code, errOut)
	}
}

func TestChangedExtensionDoesNotRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the extension is a shell script")
	}
	home := t.TempDir()
	dir := installExt(t, home, "hello", "#!/bin/sh\necho SAFE\n")
	os.WriteFile(filepath.Join(dir, "run.sh"), []byte("#!/bin/sh\necho CHANGED\n"), 0o700)
	out, errOut, code := sshrIn(t, home, "hello")
	if code != 1 || strings.Contains(out, "CHANGED") || !strings.Contains(errOut, "install it again") {
		t.Fatalf("code %d, output %q, stderr %q", code, out, errOut)
	}
}

func TestExtListAndRemove(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the extension is a shell script")
	}
	home := t.TempDir()
	out, _, _ := sshrIn(t, home, "ext", "list")
	if !strings.Contains(out, "no extensions installed") {
		t.Errorf("empty list: %q", out)
	}
	installExt(t, home, "hello", "#!/bin/sh\n")
	if out, _, _ = sshrIn(t, home, "ext", "list"); !strings.Contains(out, "hello") || !strings.Contains(out, "command") {
		t.Errorf("list: %q", out)
	}
	if out, _, code := sshrIn(t, home, "ext", "remove", "hello"); code != 0 || !strings.Contains(out, "Removed extension hello") {
		t.Errorf("remove: code %d, %q", code, out)
	}
	if _, errOut, code := sshrIn(t, home, "ext", "remove", "hello"); code != 1 || !strings.Contains(errOut, "no extension") {
		t.Errorf("remove again: code %d, %q", code, errOut)
	}
	if _, _, code := sshrIn(t, home, "ext", "remove", "../x"); code != 1 {
		t.Errorf("a path as a name: code %d", code)
	}
}

func TestExitCodeOf(t *testing.T) {
	if exitCodeOf(nil) != 0 {
		t.Error("no error is 0")
	}
	if runtime.GOOS == "windows" {
		return
	}
	err := exec.Command("sh", "-c", "exit 4").Run()
	if got := exitCodeOf(err); got != 4 {
		t.Errorf("exit 4 gives %d", got)
	}
	if got := exitCodeOf(errors.New("other")); got != 1 {
		t.Errorf("an error without a code gives %d", got)
	}
}

// every word the switch of runCLI answers to is a command of sshr, so an
// extension cannot be installed under it, a new case without help or without
// an entry in hiddenCommands fails here
func TestBuiltinNamesCoverTheSwitch(t *testing.T) {
	src, err := os.ReadFile("cli.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	start := strings.Index(body, "func runCLI(")
	if start < 0 {
		t.Fatal("runCLI is not in cli.go")
	}
	body = body[start:]
	if end := strings.Index(body[1:], "\nfunc "); end >= 0 {
		body = body[:end+1]
	}
	labels := regexp.MustCompile(`(?m)^\tcase ([^:\n]+):$`).FindAllStringSubmatch(body, -1)
	if len(labels) < 20 {
		t.Fatalf("found only %d case labels, the pattern no longer matches cli.go", len(labels))
	}
	for _, l := range labels {
		for _, w := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(l[1], -1) {
			if !isBuiltinCommand(w[1]) {
				t.Errorf("%q answers in runCLI but an extension could take the name, add it to the help or hiddenCommands", w[1])
			}
		}
	}
}

func TestExtInstallAsksAndInstalls(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the extension is a shell script")
	}
	home := t.TempDir()
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, ext.ManifestFile), []byte(`{"protocol":1,"name":"greet","version":"0.2.0","description":"says hi","command":{"default":["./run.sh","--loud"]},"kinds":["command"]}`), 0o600)
	os.WriteFile(filepath.Join(src, "run.sh"), []byte("#!/bin/sh\necho \"hi $*\"\n"), 0o700)
	// no terminal and no --yes: the details are shown and nothing is installed
	out, errOut, code := sshrIn(t, home, "ext", "install", src)
	if code != 1 || !strings.Contains(out, "Extension greet 0.2.0") || !strings.Contains(out, "./run.sh --loud") || !strings.Contains(errOut, "add --yes") {
		t.Fatalf("code %d, out %q, err %q", code, out, errOut)
	}
	if out, _, _ := sshrIn(t, home, "ext", "list"); !strings.Contains(out, "no extensions installed") {
		t.Errorf("an unconfirmed install left something: %q", out)
	}
	if out, _, code = sshrIn(t, home, "ext", "install", src, "--yes"); code != 0 || !strings.Contains(out, "Installed extension greet") || !strings.Contains(out, "Run it with: sshr greet") {
		t.Fatalf("install: code %d, %q", code, out)
	}
	if out, _, code = sshrIn(t, home, "greet", "there"); code != 0 || !strings.Contains(out, "hi --loud there") {
		t.Errorf("run: code %d, %q", code, out)
	}
	if out, _, _ = sshrIn(t, home, "ext", "install", src, "--yes"); !strings.Contains(out, "it replaces version 0.2.0") {
		t.Errorf("a second install does not say what it replaces: %q", out)
	}
}

func TestExtInstallRefusesABuiltinName(t *testing.T) {
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, ext.ManifestFile), []byte(`{"protocol":1,"name":"list","version":"1","description":"x","command":{"default":["./run.sh"]},"kinds":["command"]}`), 0o600)
	os.WriteFile(filepath.Join(src, "run.sh"), []byte("#!/bin/sh\n"), 0o700)
	home := t.TempDir()
	_, errOut, code := sshrIn(t, home, "ext", "install", src, "--yes")
	if code != 1 || !strings.Contains(errOut, "is a command of sshr") {
		t.Fatalf("code %d, stderr %q", code, errOut)
	}
	if out, _, _ := sshrIn(t, home, "ext", "list"); !strings.Contains(out, "no extensions installed") {
		t.Errorf("a refused install left something: %q", out)
	}
}

// the example extension reads the hosts back through SSHR_BIN, which needs
// the real binary, the test binary cannot stand in for it
func TestExampleExtensionGreetsTheHosts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the example is a shell script")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go tool to build sshr")
	}
	bin := filepath.Join(t.TempDir(), "sshr")
	if out, err := exec.Command(goTool, "build", "-tags", "nocgo", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("building sshr: %v\n%s", err, out)
	}
	home := t.TempDir()
	run := func(args ...string) string {
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("sshr %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	run("add", "10.0.0.9", "-u", "u", "-n", "web", "--ask-password")
	run("ext", "install", filepath.Join("..", "..", "examples", "extensions", "hello"), "--yes")
	if got := run("hello", "hi"); !strings.Contains(got, "hi, web") {
		t.Errorf("sshr hello printed %q", got)
	}
}

func TestExtImportSavesHostsOnceAndNeverTakesSecrets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the importer is a shell script")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go tool to build sshr")
	}
	bin := filepath.Join(t.TempDir(), "sshr")
	if out, err := exec.Command(goTool, "build", "-tags", "nocgo", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("building sshr: %v\n%s", err, out)
	}
	home := t.TempDir()
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, ext.ManifestFile), []byte(`{"protocol":1,"name":"fake","version":"1","description":"x","command":{"default":["./run.sh"]},"kinds":["import"]}`), 0o600)
	script := `#!/bin/sh
echo "args=$*" >&2
cat <<'JSON'
{"hosts":[
 {"key":"a","name":"alpha","host":"10.0.0.5","port":2222,"user":"deploy","tags":["prod"],"password":"hunter2"},
 {"key":"b","name":"bad","host":"not a host!","user":"u"}
]}
JSON
`
	os.WriteFile(filepath.Join(src, "run.sh"), []byte(script), 0o700)
	run := func(args ...string) (string, string, int) {
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home)
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		err := cmd.Run()
		code := 0
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		}
		return out.String(), errOut.String(), code
	}
	if _, errOut, code := run("ext", "install", src, "--yes"); code != 0 {
		t.Fatalf("install: %d %s", code, errOut)
	}
	out, errOut, code := run("ext", "import", "fake", "--source", "x")
	if code != 1 || !strings.Contains(out, "+ alpha  deploy@10.0.0.5:2222") || !strings.Contains(out, "1 added, 0 already there, 1 failed") ||
		!strings.Contains(errOut, "args=--source x") || !strings.Contains(errOut, `the field "password" is not read`) || !strings.Contains(errOut, "! b:") {
		t.Fatalf("first import: code %d\nout %q\nerr %q", code, out, errOut)
	}
	list, _, _ := run("list", "--json")
	if !strings.Contains(list, `"alpha"`) || strings.Contains(list, "hunter2") {
		t.Errorf("list after import: %s", list)
	}
	show, _, _ := run("show", "alpha")
	if !strings.Contains(show, "tags") || strings.Contains(show, "hunter2") || strings.Contains(show, "saved") {
		t.Errorf("show: %s", show)
	}
	out, _, _ = run("ext", "import", "fake")
	if !strings.Contains(out, "= alpha  already imported") || !strings.Contains(out, "0 added, 1 already there, 1 failed") {
		t.Errorf("second import: %q", out)
	}
	if _, errOut, code := run("ext", "import", "missing"); code != 1 || !strings.Contains(errOut, "no extension") {
		t.Errorf("an extension that is not installed: %d %q", code, errOut)
	}
}
