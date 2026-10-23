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
