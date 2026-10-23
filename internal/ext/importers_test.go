package ext

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// extensionsDir is taken once at start, a test may change the working
// directory
var extensionsDir, _ = filepath.Abs(filepath.Join("..", "..", "extensions"))

// lastNotes is what the last runImporter printed on stderr
var lastNotes string

// runImporter runs an importer of extensions/ the way sshr ext import does
// and parses what it prints
func runImporter(t *testing.T, name string, args ...string) []ExtHost {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the importer is a shell script")
	}
	dir := filepath.Join(extensionsDir, name)
	m, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	man, err := ParseManifest(m)
	if err != nil || !man.Has(KindImport) {
		t.Fatalf("manifest of %s: %v, kinds %v", name, err, man.Kinds)
	}
	argv, err := man.Argv(runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(dir, argv[0]), append(argv[1:], args...)...)
	cmd.Env = Env(os.Environ(), KindImport, dir, t.TempDir(), "sshr")
	var notes bytes.Buffer
	cmd.Stderr = &notes
	out, err := Collect(cmd)
	if err != nil {
		t.Fatal(err)
	}
	lastNotes = notes.String()
	hosts, warnings, err := ParseImport(out)
	if err != nil || len(warnings) > 0 {
		t.Fatalf("%s printed %s: %v %v", name, out, err, warnings)
	}
	return hosts
}

func TestRemminaImporter(t *testing.T) {
	prof := t.TempDir()
	files := map[string]string{
		"1600000000000.remmina": "[remmina]\nname=Web \"prod\"\nprotocol=SSH\nserver=10.0.0.5:2222\nusername=deploy\nssh_privatekey=/home/u/.ssh/id_ed25519\ngroup=Clients/Acme\n",
		"desk.remmina":          "[remmina]\nname=Desk\nprotocol=RDP\nserver=10.0.0.9\nssh_tunnel_server=gw\n",
		"v6 one.remmina":        "[remmina]\r\nname=v6\r\nprotocol=SSH\r\nserver=[fd00::1]:22\r\n",
		"plain.remmina":         "[other]\nserver=wrong\n[remmina]\nprotocol=SSH\nserver=db.internal\n",
		"notes.txt":             "[remmina]\nprotocol=SSH\nserver=skipped\n",
		"bigport.remmina":       "[remmina]\nprotocol=SSH\nserver=big.example:99999999999999999999\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(prof, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	hosts := runImporter(t, "remmina", prof)
	got := map[string]ExtHost{}
	for _, h := range hosts {
		got[h.Key] = h
	}
	if len(hosts) != 4 {
		t.Fatalf("hosts %+v", hosts)
	}
	if b := got["bigport"]; b.Host != "big.example" || b.Port != 0 {
		t.Errorf("a port out of range is left out, the host stays: %+v", b)
	}
	web := got["1600000000000"]
	if web.Name != `Web "prod"` || web.Host != "10.0.0.5" || web.Port != 2222 || web.User != "deploy" ||
		web.KeyFile != "/home/u/.ssh/id_ed25519" || len(web.Tags) != 2 || web.Tags[0] != "Clients" {
		t.Errorf("web %+v", web)
	}
	if v6 := got["v6 one"]; v6.Host != "fd00::1" || v6.Port != 22 {
		t.Errorf("v6 %+v", v6)
	}
	if p := got["plain"]; p.Host != "db.internal" || p.Name != "db.internal" || p.Port != 0 {
		t.Errorf("a profile without a name or port %+v", p)
	}
	for _, h := range hosts {
		if _, err := h.ToHost("remmina"); err != nil {
			t.Errorf("%s: %v", h.Key, err)
		}
	}
	if len(runImporter(t, "remmina", t.TempDir())) != 0 {
		t.Error("an empty folder gave hosts")
	}
}

func TestPuttyImporter(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"web%20prod":               "HostName=deploy@10.0.0.5\nPortNumber=2222\nProtocol=ssh\nPublicKeyFile=/home/u/k.ppk\n",
		"db":                       "HostName=db.internal\nUserName=app\nProtocol=ssh\nPortNumber=22\nProxyMethod=6\nProxyHost=gw\nProxyUsername=ops\nProxyPort=2200\nPublicKeyFile=/home/u/.ssh/id\n",
		"tel":                      "HostName=x\nProtocol=telnet\n",
		"frac":                     "HostName=f.example\nPortNumber=22.5\n",
		"Default%20Settings":       "HostName=defaults\nProtocol=ssh\n",
		"%D0%9F%D1%80%D0%BE%D0%B4": "HostName=s\r\nProtocol=ssh\r\nProxyMethod=3\r\nProxyHost=p\r\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := map[string]ExtHost{}
	for _, h := range runImporter(t, "putty", dir) {
		got[h.Key] = h
	}
	if len(got) != 4 {
		t.Fatalf("hosts %+v", got)
	}
	if f := got["frac"]; f.Host != "f.example" || f.Port != 0 {
		t.Errorf("a port that is no whole number is left out: %+v", f)
	}
	if w := got["web%20prod"]; w.Name != "web prod" || w.Host != "10.0.0.5" || w.User != "deploy" || w.Port != 2222 || w.KeyFile != "" {
		t.Errorf("web %+v, a .ppk key must be left out", w)
	}
	if d := got["db"]; d.Jump != "ops@gw:2200" || d.KeyFile != "/home/u/.ssh/id" || d.User != "app" {
		t.Errorf("db %+v", d)
	}
	if p, ok := got["%D0%9F%D1%80%D0%BE%D0%B4"]; !ok || p.Name != "Прод" || p.Host != "s" || p.Jump != "" {
		t.Errorf("a UTF-8 session name or an HTTP proxy: %+v", got)
	}
	for _, h := range got {
		if _, err := h.ToHost("putty"); err != nil {
			t.Errorf("%s: %v", h.Key, err)
		}
	}
}

// with no folder given the importer looks where PuTTY saves, and a machine
// without PuTTY gives no hosts rather than an error
func TestPuttyImporterFindsTheSessions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("PUTTYDIR", "")
	t.Setenv("PUTTYSESSIONS", "")
	if len(runImporter(t, "putty")) != 0 {
		t.Fatal("hosts without PuTTY")
	}
	sessions := filepath.Join(home, ".putty", "sessions")
	os.MkdirAll(sessions, 0o700)
	os.WriteFile(filepath.Join(sessions, "a"), []byte("HostName=a.example\n"), 0o600)
	if hosts := runImporter(t, "putty"); len(hosts) != 1 || hosts[0].Host != "a.example" {
		t.Fatalf("~/.putty/sessions: %+v", hosts)
	}
}

// a file name with a line break is skipped and never read as two names
func TestImportersSkipNamesWithLineBreaks(t *testing.T) {
	work := t.TempDir()
	t.Chdir(work)
	os.WriteFile(filepath.Join(work, "foo"), []byte("HostName=cwd.example\n[remmina]\nprotocol=SSH\nserver=cwd.example\n"), 0o600)
	for _, c := range []struct{ name, file string }{{"remmina", "x\nfoo.remmina"}, {"putty", "x\nfoo"}} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, c.file), []byte("HostName=a.example\n[remmina]\nprotocol=SSH\nserver=a.example\n"), 0o600); err != nil {
			t.Skip("this file system takes no line break in a name:", err)
		}
		if hosts := runImporter(t, c.name, dir); len(hosts) != 0 {
			t.Errorf("%s read %+v", c.name, hosts)
		}
	}
}

// a link and a file over 1 MiB are skipped, a link in a synced folder can
// point at any file
func TestImportersSkipLinksAndHugeFiles(t *testing.T) {
	for _, c := range []struct{ name, ext, body string }{
		{"remmina", ".remmina", "[remmina]\nprotocol=SSH\nserver=%s\n"},
		{"putty", "", "HostName=%s\n"},
	} {
		dir, other := t.TempDir(), t.TempDir()
		target := filepath.Join(other, "target"+c.ext)
		os.WriteFile(target, []byte(strings.ReplaceAll(c.body, "%s", "linked.example")), 0o600)
		if err := os.Symlink(target, filepath.Join(dir, "link"+c.ext)); err != nil {
			t.Skip("no symlinks here:", err)
		}
		huge := strings.ReplaceAll(c.body, "%s", "huge.example") + strings.Repeat("#", 1<<20)
		os.WriteFile(filepath.Join(dir, "huge"+c.ext), []byte(huge), 0o600)
		os.WriteFile(filepath.Join(dir, "ok"+c.ext), []byte(strings.ReplaceAll(c.body, "%s", "ok.example")), 0o600)
		hosts := runImporter(t, c.name, dir)
		if len(hosts) != 1 || hosts[0].Host != "ok.example" {
			t.Errorf("%s: %+v", c.name, hosts)
		}
	}
}

// a byte that is no UTF-8 in a profile does not stop the port from being
// read, whatever the locale
func TestRemminaImporterTakesAnyBytes(t *testing.T) {
	t.Setenv("LC_ALL", "C.UTF-8")
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.remmina"), []byte("[remmina]\nname=caf\xe9\nprotocol=SSH\nserver=h\xe9.example:2222\n"), 0o600)
	hosts := runImporter(t, "remmina", dir)
	if len(hosts) != 1 || hosts[0].Port != 2222 {
		t.Fatalf("%+v", hosts)
	}
}

// control characters, DEL and C1 controls from a session file reach
// neither the terminal nor the saved names
func TestImportersDropControlCharacters(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a%1B%5B31m"), []byte("HostName=a.example\nPublicKeyFile=/k\x1b[2J\xc2\x9bx.ppk\nProxyMethod=3\n"), 0o600)
	hosts := runImporter(t, "putty", dir)
	if len(hosts) != 1 || strings.ContainsAny(hosts[0].Name, "\x1b\x7f\u009b") {
		t.Fatalf("%+v", hosts)
	}
	if strings.ContainsAny(lastNotes, "\x1b\x7f") || strings.Contains(lastNotes, "\xc2\x9b") || !strings.Contains(lastNotes, "PuTTY key") {
		t.Errorf("notes %q", lastNotes)
	}
	rdir := t.TempDir()
	os.WriteFile(filepath.Join(rdir, "r.remmina"), []byte("[remmina]\nname=we\x7fb\xc2\x9b\x1b[0m\nprotocol=SSH\nserver=r.example\n"), 0o600)
	if hosts := runImporter(t, "remmina", rdir); len(hosts) != 1 || hosts[0].Name != "web[0m" {
		t.Errorf("remmina %+v", hosts)
	}
}

// the key is the file name as PuTTY wrote it, so names that decode alike
// stay apart, a name that is not UTF-8 keeps its escapes
func TestPuttyImporterKeysAndNames(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"A", "%41", "%C8", "%C9", "q%22b%5C", "%F0%9F%98%80"} {
		os.WriteFile(filepath.Join(dir, n), []byte("HostName=h.example\n"), 0o600)
	}
	got := map[string]string{}
	for _, h := range runImporter(t, "putty", dir) {
		got[h.Key] = h.Name
	}
	want := map[string]string{"A": "A", "%41": "A", "%C8": "%C8", "%C9": "%C9", "q%22b%5C": `q"b\`, "%F0%9F%98%80": "😀"}
	if len(got) != len(want) {
		t.Fatalf("%q", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: name %q, want %q", k, got[k], v)
		}
	}
	if HostID("putty", "A") == HostID("putty", "%41") {
		t.Error("two files share a host")
	}
}
