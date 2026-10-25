package sshcmd

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"sshr.dev/internal/settings"
)

// a listed host logs in only with a certificate signed for this login:
// the options name the certificate file and no password or other key, the
// agent serves a key with a certificate for the principal, the file and
// the agent go when ssh ends, a hop goes through sshr
func TestCertLogin(t *testing.T) {
	certHome(t)
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv("SSH_AUTH_SOCK", "/user/agent")
	ca, err := InitSoftwareCA(false)
	if err != nil {
		t.Fatal(err)
	}
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Name: "web", Host: "10.0.0.1", User: "deploy", PasswordMode: PasswordSaved, Password: "pw", Jump: "user@bastion"})
	if err != nil {
		t.Fatal(err)
	}
	st, _ := settings.Load()
	st.EnableCert(h.ID, CertTarget(h), []string{"deploy"})
	if err := settings.Save(st); err != nil {
		t.Fatal(err)
	}
	h, _ = s.Find(h.ID)
	args, err := s.ConnectArgs(h)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Join(args, " ")
	if h.CertFile() == "" || !strings.Contains(line, "-i "+h.CertFile()) {
		t.Fatalf("no certificate file in %s", line)
	}
	for _, want := range []string{"IdentitiesOnly=yes", "PasswordAuthentication=no", "ForwardAgent=no", "ProxyCommand="} {
		if !strings.Contains(line, want) {
			t.Errorf("no %s in %s", want, line)
		}
	}
	if strings.Contains(line, "keyboard-interactive") || strings.Contains(line, " -J ") {
		t.Errorf("a password or a plain jump with a certificate: %s", line)
	}
	cmd := exec.Command("true")
	stop, err := AttachAuth(cmd, h)
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range cmd.Env {
		if strings.HasPrefix(kv, askpassSockEnv+"=") {
			t.Errorf("the saved password went to ssh: %s", kv)
		}
	}
	file, err := os.ReadFile(h.CertFile())
	if err != nil {
		t.Fatal(err)
	}
	k, _, _, _, err := ssh.ParseAuthorizedKey(file)
	if err != nil {
		t.Fatal(err)
	}
	cert, ok := k.(*ssh.Certificate)
	if !ok {
		t.Fatalf("the file holds a %T", k)
	}
	caPub, _ := ca.PublicKey()
	checker := ssh.CertChecker{IsUserAuthority: func(k ssh.PublicKey) bool { return string(k.Marshal()) == string(caPub.Marshal()) }}
	if err := checker.CheckCert("deploy", cert); err != nil {
		t.Errorf("the certificate: %v", err)
	}
	sock := ""
	for _, kv := range cmd.Env {
		if v, ok := strings.CutPrefix(kv, "SSH_AUTH_SOCK="); ok {
			sock = v
		}
	}
	c, err := dialAgent(sock)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := agent.NewClient(c).List()
	c.Close()
	if err != nil || len(keys) != 1 || string(keys[0].Marshal()) != string(cert.Marshal()) {
		t.Fatalf("agent keys %v %v", keys, err)
	}
	stop()
	if _, err := os.Stat(h.CertFile()); !os.IsNotExist(err) {
		t.Errorf("the certificate file stayed: %v", err)
	}

	// a host that also needs a hardware key is refused, there is no token
	// authority yet
	st.RequireHardwareKey(h.ID)
	settings.Save(st)
	if _, err := s.ConnectArgs(h); err == nil || !strings.Contains(err.Error(), "hardware key") {
		t.Errorf("a host on both lists: %v", err)
	}
	st.ReleaseHardwareKey(h.ID)
	// a host repointed since it was listed is refused
	st.HardwareKey = ""
	settings.Save(st)
	h.Host = "10.0.0.9"
	if _, err := s.ConnectArgs(h); err == nil || !strings.Contains(err.Error(), "points elsewhere") {
		t.Errorf("a repointed host: %v", err)
	}
}

// a real ssh logs in to a real sshd that trusts the authority, with the
// options and the agent of a certificate login and nothing else, skipped
// where no sshd is installed
func TestCertLoginToSSHD(t *testing.T) {
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		t.Skip("no sshd")
	}
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("no ssh")
	}
	certHome(t)
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv("SSHR_REUSE", "0")
	ca, err := InitSoftwareCA(false)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	hostKey := filepath.Join(dir, "hostkey")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", hostKey).CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen: %v %s", err, out)
	}
	caFile := filepath.Join(dir, "ca.pub")
	os.WriteFile(caFile, []byte(ca.Pub+"\n"), 0o600)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	conf := filepath.Join(dir, "sshd_config")
	os.WriteFile(conf, []byte(fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nTrustedUserCAKeys %s\nAuthorizedKeysFile none\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nPidFile %s\n",
		port, hostKey, caFile, filepath.Join(dir, "sshd.pid"))), 0o600)
	srv := exec.Command(sshd, "-D", "-e", "-f", conf)
	var srvLog strings.Builder
	srv.Stderr = &srvLog
	if err := srv.Start(); err != nil {
		t.Skipf("sshd does not start: %v", err)
	}
	t.Cleanup(func() { srv.Process.Kill(); srv.Wait() })
	for i := 0; i < 50; i++ {
		if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			c.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Name: "local", Host: "127.0.0.1", Port: port, User: me.Username})
	if err != nil {
		t.Fatal(err)
	}
	st, _ := settings.Load()
	st.EnableCert(h.ID, CertTarget(h), []string{me.Username})
	settings.Save(st)
	h, _ = s.Find(h.ID)
	args, err := s.ConnectArgs(h)
	if err != nil {
		t.Fatal(err)
	}
	args = append(args, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-F", "/dev/null", h.Dest(), "echo cert-ok")
	cmd := exec.Command(sshBin, args...)
	stop, err := AttachAuth(cmd, h)
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.CombinedOutput()
	stop()
	if err != nil || !strings.Contains(string(out), "cert-ok") {
		t.Fatalf("ssh with the certificate: %v\n%s\nsshd:\n%s", err, out, srvLog.String())
	}
}

// a host the ssh config of the user gives its own key is refused, ssh
// would offer that key next to the certificate, a certificate login
// never shares a master connection
func TestCertLoginRefusesConfigKeys(t *testing.T) {
	certHome(t)
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	if _, err := InitSoftwareCA(false); err != nil {
		t.Fatal(err)
	}
	s := &Store{Dir: t.TempDir()}
	h, _ := s.Add(Host{Name: "web", Host: "10.0.0.1", User: "deploy"})
	st, _ := settings.Load()
	st.EnableCert(h.ID, CertTarget(h), []string{"deploy"})
	settings.Save(st)
	args, err := s.ConnectArgs(h)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Join(args, " ")
	if !strings.Contains(line, "ControlMaster=no") || !strings.Contains(line, "ControlPath=none") {
		t.Errorf("a certificate login may share a connection: %s", line)
	}
	conf := filepath.Join(t.TempDir(), "config")
	os.WriteFile(conf, []byte("Host 10.0.0.1\n  IdentityFile ~/.ssh/longlived\n"), 0o600)
	sshUserConfig = conf
	t.Cleanup(func() { sshUserConfig = "" })
	if _, err := s.ConnectArgs(h); err == nil || !strings.Contains(err.Error(), "longlived") {
		t.Errorf("a host with a key in the ssh config: %v", err)
	}
}

// a certificate file older than an hour is from a login whose sshr was
// killed, it goes at the next certificate login, a fresh one stays
func TestSweepCertFiles(t *testing.T) {
	dir := t.TempDir()
	old, fresh := filepath.Join(dir, "cert-aaaa.pub"), filepath.Join(dir, "cert-bbbb.pub")
	other := filepath.Join(dir, "master-socket")
	for _, f := range []string{old, fresh, other} {
		os.WriteFile(f, []byte("x"), 0o600)
	}
	now := time.Now()
	os.Chtimes(old, now.Add(-2*time.Hour), now.Add(-2*time.Hour))
	os.Chtimes(other, now.Add(-2*time.Hour), now.Add(-2*time.Hour))
	sweepCertFiles(dir, now)
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("an old certificate file stayed")
	}
	for _, f := range []string{fresh, other} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("%s went: %v", f, err)
		}
	}
}
