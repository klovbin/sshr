package app

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestExportSSHConfig(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "my key")
	os.WriteFile(key, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600)
	cfg := filepath.Join(dir, "config")
	os.WriteFile(cfg, []byte("Host taken\n  HostName 10.9.9.9\n"), 0o600)
	old := sshConfigFile
	sshConfigFile = cfg
	defer func() { sshConfigFile = old }()

	s := &Store{Dir: filepath.Join(dir, "hosts"), SSHConfigOut: filepath.Join(dir, "ssh_config")}
	os.MkdirAll(s.Dir, 0o700)
	add := func(h Host) {
		t.Helper()
		if _, err := s.Add(h); err != nil {
			t.Fatal(err)
		}
	}
	add(Host{Name: "bastion", Host: "10.0.0.1", User: "jump", Key: key})
	add(Host{Name: "web prod", Host: "10.0.0.2", User: "deploy", Port: 2222, Jump: "bastion,edge.example.com", PasswordMode: PasswordAsk})
	add(Host{Name: "taken", Host: "10.0.0.3", User: "u", PasswordMode: PasswordAsk})
	sock := filepath.Join(dir, "a%b.sock")
	add(Host{Name: "agent", Host: "10.0.0.4", User: "u", KeyMode: KeyAgent, Agent: sock, PasswordMode: PasswordAsk})

	if s.SSHConfigExported() {
		t.Fatal("export reported before install")
	}
	items, err := s.InstallSSHConfig()
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]ExportItem{}
	for _, it := range items {
		by[it.Name] = it
	}
	if by["taken"].Skipped == "" || by["web prod"].Alias != "web-prod" {
		t.Fatalf("items = %+v", items)
	}
	out, _ := os.ReadFile(s.SSHConfigOut)
	for _, want := range []string{
		"Host bastion\n  HostName 10.0.0.1\n  User jump\n  IdentityFile \"" + key + "\"\n  IdentitiesOnly yes\n",
		"Host web-prod\n  HostName 10.0.0.2\n  User deploy\n  Port 2222\n  ProxyJump bastion,edge.example.com\n",
		"IdentityAgent \"" + strings.ReplaceAll(sock, "%", "%%") + "\"",
	} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("export lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(string(out), "10.0.0.3") {
		t.Fatal("a host shadowing the user's alias was exported")
	}
	user, _ := os.ReadFile(cfg)
	if !strings.HasPrefix(string(user), s.includeLine()+"\nHost taken\n") {
		t.Fatalf("user config:\n%s", user)
	}

	// ssh itself reads the result the same way
	if sshPath, err := exec.LookPath("ssh"); err == nil {
		g, err := sshG("web-prod", cfg)
		if err != nil {
			t.Fatal(err)
		}
		if g["hostname"][0] != "10.0.0.2" || g["port"][0] != "2222" || g["proxyjump"][0] != "bastion,edge.example.com" {
			// what ssh made of the Include line
			ver, _ := exec.Command(sshPath, "-V").CombinedOutput()
			dbg, _ := exec.Command(sshPath, "-vvv", "-G", "-F", cfg, "web-prod").CombinedOutput()
			var lines []string
			for _, l := range strings.Split(string(dbg), "\n") {
				if strings.Contains(strings.ToLower(l), "include") || strings.Contains(l, "Reading configuration") {
					lines = append(lines, l)
				}
			}
			t.Fatalf("ssh %s (%s) got hostname %v port %v for web-prod\ninclude line: %s\n%s",
				sshPath, strings.TrimSpace(string(ver)), g["hostname"], g["port"], s.includeLine(), strings.Join(lines, "\n"))
		}
	}

	// a change rewrites the export, a second install adds no second line
	h, _ := s.Find("taken")
	s.Delete(h.ID)
	h, _ = s.Find("agent")
	s.Update(h.ID, Host{Name: "agent2", Host: "10.0.0.4", User: "u", KeyMode: KeyAgent, Agent: sock, PasswordMode: PasswordAsk})
	out, _ = os.ReadFile(s.SSHConfigOut)
	if !strings.Contains(string(out), "Host agent2\n") || strings.Contains(string(out), "Host agent\n") {
		t.Fatalf("export not rewritten on update:\n%s", out)
	}
	s.InstallSSHConfig()
	user, _ = os.ReadFile(cfg)
	if strings.Count(string(user), "Include") != 1 {
		t.Fatalf("Include added twice:\n%s", user)
	}

	if err := s.UninstallSSHConfig(); err != nil {
		t.Fatal(err)
	}
	user, _ = os.ReadFile(cfg)
	if string(user) != "Host taken\n  HostName 10.9.9.9\n" {
		t.Fatalf("user config after uninstall:\n%s", user)
	}
	if _, err := os.Stat(s.SSHConfigOut); !os.IsNotExist(err) {
		t.Fatal("export file left after uninstall")
	}
}

func TestExportRejectsInjection(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	old := sshConfigFile
	sshConfigFile = filepath.Join(t.TempDir(), "none")
	defer func() { sshConfigFile = old }()
	h := Host{ID: "x", Name: "evil", Host: "a\n  ProxyCommand touch /tmp/p", PasswordMode: PasswordAsk}
	if _, _, err := s.exportBlock(&h, "evil", nil); err == nil {
		t.Fatal("newline in the address was accepted")
	}
	h = Host{ID: "x", Name: "evil", Host: "a", Key: "/k\"\n  ProxyCommand x"}
	if _, _, err := s.exportBlock(&h, "evil", nil); err == nil {
		t.Fatal("quote in the key path was accepted")
	}
	var buf bytes.Buffer
	if _, err := s.WriteSSHConfig(&buf); err != nil {
		t.Fatal(err)
	}
}

func TestExportLeavesLinkedConfig(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	os.WriteFile(real, []byte("Host a\n"), 0o600)
	link := filepath.Join(dir, "config")
	os.Symlink(real, link)
	old := sshConfigFile
	sshConfigFile = link
	defer func() { sshConfigFile = old }()
	s := &Store{Dir: filepath.Join(dir, "hosts"), SSHConfigOut: filepath.Join(dir, "ssh_config")}
	os.MkdirAll(s.Dir, 0o700)
	if _, err := s.InstallSSHConfig(); err == nil || !strings.Contains(err.Error(), "Include") {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(real); string(b) != "Host a\n" {
		t.Fatal("linked config was edited")
	}
	if !s.SSHConfigExported() {
		t.Fatal("export not written when only the Include line is left")
	}
}

func TestExportKeepsLongConfigLines(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	long := "# " + strings.Repeat("x", 100<<10)
	orig := "Host a\r\n" + long + "\nHost b\n  HostName 10.0.0.2\n"
	os.WriteFile(cfg, []byte(orig), 0o600)
	old := sshConfigFile
	sshConfigFile = cfg
	defer func() { sshConfigFile = old }()
	s := &Store{Dir: filepath.Join(dir, "hosts"), SSHConfigOut: filepath.Join(dir, "ssh_config")}
	os.MkdirAll(s.Dir, 0o700)
	if _, err := s.InstallSSHConfig(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(cfg)
	if want := s.includeLine() + "\n" + orig; string(b) != want {
		t.Fatalf("install changed the rest of the file, got %d bytes, want %d", len(b), len(want))
	}
	if err := s.UninstallSSHConfig(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(cfg); string(b) != orig {
		t.Fatalf("uninstall did not restore the file, got %d bytes, want %d", len(b), len(orig))
	}
}

func TestWriteFileAtomicConcurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host.json")
	var wg sync.WaitGroup
	errs := make(chan error, 400)
	for g := 0; g < 8; g++ {
		data := bytes.Repeat([]byte{byte('a' + g)}, 64<<10)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if err := WriteFileAtomic(path, data, 0o600); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if len(b) != 64<<10 || bytes.Count(b, b[:1]) != len(b) {
		t.Fatal("the file is a mix of two writers")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(left) > 0 {
		t.Fatalf("temp files left: %v", left)
	}
}
