package ext

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// runImporter runs an importer of extensions/ the way sshr ext import does
// and parses what it prints
func runImporter(t *testing.T, name string, args ...string) []ExtHost {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the importer is a shell script")
	}
	dir, err := filepath.Abs(filepath.Join("..", "..", "extensions", name))
	if err != nil {
		t.Fatal(err)
	}
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
	out, err := Collect(cmd)
	if err != nil {
		t.Fatal(err)
	}
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
	if len(hosts) != 3 {
		t.Fatalf("hosts %+v", hosts)
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
	if len(got) != 3 {
		t.Fatalf("hosts %+v", got)
	}
	if w := got["web prod"]; w.Host != "10.0.0.5" || w.User != "deploy" || w.Port != 2222 || w.KeyFile != "" {
		t.Errorf("web %+v, a .ppk key must be left out", w)
	}
	if d := got["db"]; d.Jump != "ops@gw:2200" || d.KeyFile != "/home/u/.ssh/id" || d.User != "app" {
		t.Errorf("db %+v", d)
	}
	if p, ok := got["Прод"]; !ok || p.Host != "s" || p.Jump != "" {
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
