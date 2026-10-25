package sshconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportSSHConfig(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "work_key")
	os.WriteFile(key, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600)
	os.MkdirAll(filepath.Join(dir, "conf.d"), 0o700)
	os.WriteFile(filepath.Join(dir, "conf.d", "more.conf"), []byte("Host db\n  HostName 10.0.0.6\n  User pg\n  Include config\n"), 0o600)
	cfg := filepath.Join(dir, "config")
	os.WriteFile(cfg, []byte(`# test config
Include conf.d/*.conf
Host web web2
  HostName 10.0.0.5
  User deploy
  Port 2222
  IdentityFile `+key+`
  ProxyJump bastion
  LocalForward 5432 localhost:5432
  LocalForward 127.0.0.1:8080 [::1]:80
  RemoteForward 9000 localhost:3000
  DynamicForward 1080
Host op
  HostName op.example.com
  IdentityAgent ~/.1password/agent.sock
Host viaproxy
  HostName 10.0.0.9
  ProxyCommand nc %h %p
Host missing
  HostName 10.0.0.10
  IdentityFile ~/nope/key
Host *.corp !skip
  User corp
`), 0o600)
	old := sshConfigFile
	sshConfigFile = cfg
	defer func() { sshConfigFile = old }()

	aliases, err := SSHConfigAliases()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(aliases, ","); got != "db,web,web2,op,viaproxy,missing" {
		t.Fatalf("aliases = %s", got)
	}
	s := &Store{Dir: t.TempDir()}
	s.Add(Host{Name: "web2", Host: "1.2.3.4", User: "x"})
	items, err := s.ImportSSHConfig(false)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]ImportItem{}
	for _, it := range items {
		by[it.Alias] = it
	}
	web := by["web"].Host
	if web == nil || web.Host != "10.0.0.5" || web.User != "deploy" || web.Port != 2222 || web.Key != key || web.Jump != "bastion" {
		t.Fatalf("web = %+v %v", web, by["web"])
	}
	if got := FormatForwards(web.Forwards); got != "d1 -D 1080\nl1 -L 5432:localhost:5432\nl2 -L 127.0.0.1:8080:[::1]:80\nr1 -R 9000:localhost:3000" {
		t.Errorf("forwards =\n%s", got)
	}
	if by["web2"].Skipped == "" {
		t.Error("web2 imported over a saved host of the same name")
	}
	if op := by["op"].Host; op == nil || op.KeyMode != KeyAgent || op.Agent != AgentOnePassword {
		t.Errorf("op = %+v", op)
	}
	if vp := by["viaproxy"].Host; vp == nil || vp.Host != "viaproxy" || len(by["viaproxy"].Notes) == 0 {
		t.Errorf("viaproxy = %+v %v", vp, by["viaproxy"].Notes)
	}
	if m := by["missing"]; m.Host == nil || m.Host.Key != "" || len(m.Notes) == 0 {
		t.Errorf("missing key = %+v", m)
	}
	// a second run adds nothing
	items, _ = s.ImportSSHConfig(false)
	for _, it := range items {
		if it.Skipped == "" {
			t.Errorf("%s imported twice", it.Alias)
		}
	}
}
