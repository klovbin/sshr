package ext

import (
	"bytes"
	"fmt"
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
	// a proxy user or host of control characters only gives no "@gw" and
	// no empty jump (#324)
	jdir := t.TempDir()
	os.WriteFile(filepath.Join(jdir, "u"), []byte("HostName=u.example\nProxyMethod=6\nProxyHost=gw.example\nProxyUsername=\x1b\x7f\n"), 0o600)
	os.WriteFile(filepath.Join(jdir, "h"), []byte("HostName=h.example\nProxyMethod=6\nProxyHost=\x1b\xc2\x9b\n"), 0o600)
	for _, h := range runImporter(t, "putty", jdir) {
		if want := map[string]string{"u": "gw.example", "h": ""}[h.Key]; h.Jump != want {
			t.Errorf("%s: jump %q, want %q", h.Key, h.Jump, want)
		}
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

// TestPuttyWindowsImporter runs putty.ps1, the importer of Windows, on a
// .reg file as regedit writes it (UTF-16 with a BOM), with pwsh where it
// is installed, the same sessions give the same hosts as putty.sh
func TestPuttyWindowsImporter(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("no pwsh here")
	}
	reg := "Windows Registry Editor Version 5.00\r\n\r\n" +
		`[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\Default%20Settings]` + "\r\n" +
		`"HostName"="default.example"` + "\r\n\r\n" +
		`[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\web%20prod]` + "\r\n" +
		`"HostName"="deploy@10.0.0.5"` + "\r\n" +
		`"PortNumber"=dword:00000016` + "\r\n" +
		`"Protocol"="ssh"` + "\r\n" +
		`"PublicKeyFile"="C:\\keys\\web.ppk"` + "\r\n" +
		`"ProxyMethod"=dword:00000006` + "\r\n" +
		`"ProxyHost"="gw.example"` + "\r\n" +
		`"ProxyUsername"="ops"` + "\r\n" +
		`"ProxyPort"=dword:00000824` + "\r\n\r\n" +
		`[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\%D0%B1%D0%B0%D0%B7%D0%B0]` + "\r\n" +
		`"HostName"="db.local"` + "\r\n" +
		`"UserName"="u"` + "\r\n" +
		`"PortNumber"=dword:00000d05` + "\r\n" +
		`"PublicKeyFile"="C:\\keys\\id_ed25519"` + "\r\n" +
		`"ProxyMethod"=dword:00000002` + "\r\n\r\n" +
		`[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\switch]` + "\r\n" +
		`"HostName"="sw1"` + "\r\n" +
		`"Protocol"="telnet"` + "\r\n\r\n" +
		`[HKEY_CURRENT_USER\Software\Other]` + "\r\n" +
		`"HostName"="other.example"` + "\r\n"
	// a second file, every file given is read (#319)
	second := "Windows Registry Editor Version 5.00\r\n\r\n" +
		`[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\work]` + "\r\n" +
		`"HostName"="work.example"` + "\r\n"
	tmp := t.TempDir()
	var files []string
	for i, text := range []string{reg, second} {
		utf16 := []byte{0xff, 0xfe}
		for _, r := range text {
			utf16 = append(utf16, byte(r), byte(r>>8))
		}
		file := filepath.Join(tmp, fmt.Sprintf("putty%d.reg", i))
		if err := os.WriteFile(file, utf16, 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	// a REGEDIT4 file in Windows-1252 and a UTF-8 one without a BOM (#320)
	for name, body := range map[string]string{
		"ansi.reg": "REGEDIT4\r\n\r\n[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\ansi]\r\n\"HostName\"=\"ansi.example\"\r\n\"UserName\"=\"jos\xe9\"\r\n",
		"utf8.reg": "Windows Registry Editor Version 5.00\n\n[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\utf8]\n\"HostName\"=\"utf8.example\"\n\"UserName\"=\"jürgen\"\n",
	} {
		file := filepath.Join(tmp, name)
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	// a link is skipped, not followed (#323)
	link := filepath.Join(tmp, "link.reg")
	if err := os.Symlink(files[0], link); err == nil {
		files = append(files, link)
	}
	dir := filepath.Join(extensionsDir, "putty")
	args := append([]string{"-NoProfile", "-NonInteractive", "-File", filepath.Join(dir, "putty.ps1")}, files...)
	cmd := exec.Command(pwsh, args...)
	cmd.Env = Env(os.Environ(), KindImport, dir, t.TempDir(), "sshr")
	var notes bytes.Buffer
	cmd.Stderr = &notes
	out, err := Collect(cmd)
	if err != nil {
		t.Fatalf("%v: %s", err, notes.String())
	}
	hosts, warnings, err := ParseImport(out)
	if err != nil || len(warnings) > 0 || len(hosts) != 5 || hosts[2].Host != "work.example" {
		t.Fatalf("printed %s: %v %v", out, err, warnings)
	}
	users := map[string]string{}
	for _, h := range hosts[3:] {
		users[h.Host] = h.User
	}
	if users["ansi.example"] != "josé" || users["utf8.example"] != "jürgen" {
		t.Errorf("charsets: %q", users)
	}
	web, db := hosts[0], hosts[1]
	if web.Key != "web%20prod" || web.Name != "web prod" || web.Host != "10.0.0.5" || web.User != "deploy" ||
		web.Port != 22 || web.KeyFile != "" || web.Jump != "ops@gw.example:2084" {
		t.Errorf("web: %+v", web)
	}
	if db.Name != "база" || db.Port != 3333 || db.User != "u" || db.KeyFile != `C:\keys\id_ed25519` || db.Jump != "" {
		t.Errorf("db: %+v", db)
	}
	if n := notes.String(); !strings.Contains(n, "puttygen") || !strings.Contains(n, "ProxyMethod 2") ||
		strings.HasSuffix(files[len(files)-1], "link.reg") && !strings.Contains(n, "is a link") {
		t.Errorf("notes: %s", n)
	}
	for _, h := range hosts {
		if _, err := h.ToHost("putty"); err != nil {
			t.Errorf("%s: %v", h.Name, err)
		}
	}
}

// runPwshImporter runs the PowerShell script of an importer with pwsh,
// the importers of Windows are checked this way on any system, the test
// is skipped where pwsh is missing
func runPwshImporter(t *testing.T, name string, files ...string) ([]ExtHost, string) {
	t.Helper()
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("no pwsh here")
	}
	dir := filepath.Join(extensionsDir, name)
	args := append([]string{"-NoProfile", "-NonInteractive", "-File", filepath.Join(dir, name+".ps1")}, files...)
	cmd := exec.Command(pwsh, args...)
	cmd.Env = Env(os.Environ(), KindImport, dir, t.TempDir(), "sshr")
	var notes bytes.Buffer
	cmd.Stderr = &notes
	out, err := Collect(cmd)
	if err != nil {
		t.Fatalf("%v: %s", err, notes.String())
	}
	hosts, warnings, err := ParseImport(out)
	if err != nil || len(warnings) > 0 {
		t.Fatalf("%s printed %s: %v %v", name, out, err, warnings)
	}
	return hosts, notes.String()
}

// TestMobaXtermImporter reads an export of MobaXterm in Windows-1252 with
// a folder, two gateways, an RDP session and a session outside the
// bookmarks, and a .moba file of one session
func TestMobaXtermImporter(t *testing.T) {
	ini := "[Bookmarks]\r\nSubRep=\r\nImgNum=42\r\n" +
		"web \x80=#109#0%10.0.0.5%2222%deploy%%-1%-1%%gw1.example__PIPE__gw2.example%22__PIPE__2200%ops__PIPE__%0%0%0%_CurrentDrive_:\\keys\\web.ppk%%-1%0%0%2%socks.example%1080%%0%0%1%%0%%%%0%-1%-1%0#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%0%_Std_Colors_0_%80%24%0%0%-1%<none>%%0%0%-1%-1#0# #-1\r\n" +
		"desk=#91#4%10.0.0.9%3389%%0%0%0%0%-1%0%0%-1#MobaFont#0# #-1\r\n" +
		"a=1= #109#0%a1.example%22%%%-1#MobaFont#0# #-1\r\n" +
		"a=2=#109#0%a2.example%22%%%-1#MobaFont#0# #-1\r\n" +
		"gw=#109#0%gw.example%22%%%-1%-1%%j1.example__PIPE__j2.example%22__PIPE__22%<default>__PIPE__me%0#MobaFont#0# #-1\r\n" +
		"x__DIEZE__1=#109#0%esc.example%22%u__PERCENT__1%%-1%-1%%%%%0%-1%0%_CurrentDrive_:\\k__DIEZE__1%%-1#MobaFont#0# #-1\r\n" +
		"\r\n[Bookmarks_1]\r\nSubRep=Clients\\Acme\r\nImgNum=41\r\n" +
		"db=#109#0%db.local%22%<default>%%-1%-1%%%%%0%-1%0%_CurrentDrive_:\\keys\\id_ed25519%%-1%0%0%0%%1080%%0#MobaFont#0# #-1\r\n" +
		"web \x80=#109#0%10.1.0.5%22%%%-1%-1%%%%%0%-1%0%%%-1%0%0%0%%1080%%0#MobaFont#0# #-1\r\n" +
		"\r\n[Misc]\r\nnot=#109#0%misc.example%22%u%%-1\r\n"
	tmp := t.TempDir()
	file := filepath.Join(tmp, "export.mxtsessions")
	moba := filepath.Join(tmp, "one.moba")
	if os.WriteFile(file, []byte(ini), 0o600) != nil || os.WriteFile(moba, []byte("single=#109#0%single.example%22%root%%-1%-1#MobaFont#0# #-1\r\n"), 0o600) != nil {
		t.Fatal("cannot write the files")
	}
	// _CurrentDrive_ of an export is the drive of Windows (#329)
	t.Setenv("SystemDrive", "D:")
	hosts, notes := runPwshImporter(t, "mobaxterm", file, moba)
	got := map[string]ExtHost{}
	for _, h := range hosts {
		got[h.Key] = h
	}
	if len(hosts) != 8 {
		t.Fatalf("%+v", hosts)
	}
	// a name with = keeps it (#327)
	if got["a=1"].Host != "a1.example" || got["a=2"].Host != "a2.example" {
		t.Errorf("names with =: %+v", got)
	}
	// <default> as a gateway user is no user (#328)
	if j := got["gw"].Jump; j != "j1.example,me@j2.example" {
		t.Errorf("gateway users: %q", j)
	}
	// the escapes of MobaXterm are decoded (#329)
	if e := got["x#1"]; e.User != "u%1" || e.KeyFile != `D:\k#1` {
		t.Errorf("escapes: %+v", got)
	}
	web := got["web \u20ac"]
	if web.Host != "10.0.0.5" || web.Port != 2222 || web.User != "deploy" || web.KeyFile != "" ||
		web.Jump != "ops@gw1.example,gw2.example:2200" || len(web.Tags) != 0 {
		t.Errorf("web: %+v", web)
	}
	db := got[`Clients\Acme\db`]
	if db.Host != "db.local" || db.User != "" || db.KeyFile != `D:\keys\id_ed25519` || db.Jump != "" ||
		strings.Join(db.Tags, ",") != "Clients,Acme" {
		t.Errorf("db: %+v", db)
	}
	if got[`Clients\Acme\web `+"\u20ac"].Host != "10.1.0.5" || got["single"].User != "root" {
		t.Errorf("%+v", got)
	}
	if !strings.Contains(notes, "puttygen") || !strings.Contains(notes, "proxy (type 2)") {
		t.Errorf("notes: %s", notes)
	}
	for _, h := range hosts {
		if _, err := h.ToHost("mobaxterm"); err != nil {
			t.Errorf("%s: %v", h.Name, err)
		}
	}
}
