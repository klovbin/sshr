package app

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// sshBanner listens on a local port and greets every connection like sshd
func sshBanner(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-test\r\n"))
			c.Close()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// closedPort is a local port nothing listens on, a connect is refused
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func TestGatewayOnlyWhenDirectIsDown(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	up := Host{Name: "up", Host: "127.0.0.1", Port: sshBanner(t), User: "u", PasswordMode: PasswordAsk, Gateway: "ops@gw:2222"}
	args, err := s.ConnectArgs(&up)
	if err != nil {
		t.Fatal(err)
	}
	if line := strings.Join(args, " "); strings.Contains(line, "-J") || up.Via() != "" {
		t.Errorf("a host that answers went through the gateway: %s", line)
	}

	down := Host{Name: "down", Host: "127.0.0.1", Port: closedPort(t), User: "u", PasswordMode: PasswordAsk, Gateway: "ops@gw:2222"}
	args, err = s.ConnectArgs(&down)
	if err != nil {
		t.Fatal(err)
	}
	if line := strings.Join(args, " "); !strings.Contains(line, "-J ops@gw:2222") || down.Via() != "ops@gw:2222" {
		t.Errorf("a host down directly did not go through the gateway: %s", line)
	}
}

func TestNoGatewayNoCheck(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	h := Host{Name: "h", Host: "127.0.0.1", Port: closedPort(t), User: "u", PasswordMode: PasswordAsk}
	args, err := s.ConnectArgs(&h)
	if err != nil {
		t.Fatal(err)
	}
	if h.Via() != "" || strings.Contains(strings.Join(args, " "), "-J") {
		t.Errorf("a host without a gateway was checked or rerouted: %v", args)
	}
	// both set, as in a file edited by hand: the jump hosts win, no check
	j := Host{Name: "j", Host: "10.0.0.9", Port: 22, User: "u", PasswordMode: PasswordAsk, Jump: "ops@gw", Gateway: "other@gw2"}
	if _, err := s.ConnectArgs(&j); err != nil {
		t.Fatal(err)
	}
	if j.Via() != "ops@gw" {
		t.Errorf("a host with jump hosts was checked: via %q", j.Via())
	}
}

func TestGatewayRules(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	if _, err := s.Add(Host{Name: "a", Host: "h", User: "u", PasswordMode: PasswordAsk, Jump: "gw", Gateway: "gw2"}); err == nil {
		t.Error("a host with both jump hosts and a gateway was saved")
	}
	if _, err := s.Add(Host{Name: "b", Host: "h", User: "u", PasswordMode: PasswordAsk, Gateway: "b"}); err == nil {
		t.Error("a host with itself as the gateway was saved")
	}
	if _, err := s.Add(Host{Name: "c", Host: "h", User: "u", PasswordMode: PasswordAsk, Gateway: "gw;id"}); err == nil {
		t.Error("a gateway with a shell character was saved")
	}
	h, err := s.Add(Host{Name: "d", Host: "h", User: "u", PasswordMode: PasswordAsk, Gateway: " ops@gw:2222 "})
	if err != nil || h.Gateway != "ops@gw:2222" {
		t.Fatalf("gateway = %q, %v", h.Gateway, err)
	}
}

// a password sealed before gateways existed still opens, a gateway added
// through sshr keeps it, one added in the file by hand does not
func TestGatewayAndSavedPassword(t *testing.T) {
	useMockKeychain(t)
	if destination(Host{Host: "h", User: "u", Port: 22}) != "h\x00u\x0022\x00" {
		t.Error("the destination of a host without a gateway changed, older seals would not open")
	}
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Name: "w", Host: "10.0.0.1", User: "u", PasswordMode: PasswordSaved, Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.Dir, h.ID+".json")
	b, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(b), `"user": "u",`, `"user": "u", "gateway": "evil@203.0.113.66",`, 1)), 0o600)
	tampered, _ := s.Find(h.ID)
	if tampered.Gateway == "" {
		t.Fatal("the hand edit did not take")
	}
	if err := Unlock(tampered); err == nil {
		t.Fatal("the password opened for a gateway added outside sshr")
	}
	os.WriteFile(path, b, 0o600)
	if _, err := s.SetGateway(h.ID, "bastion"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Find(h.ID)
	if err := Unlock(got); err != nil || got.Password != "pw" {
		t.Fatalf("after adding a gateway in sshr: %v %q", err, got.Password)
	}
}

// a form that has no gateway field (the app) keeps the gateway on save,
// jump hosts set in it drop the gateway
func TestUpdateKeepsGateway(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Name: "db", Host: "10.0.0.5", User: "u", PasswordMode: PasswordAsk, Gateway: "bastion"})
	if err != nil {
		t.Fatal(err)
	}
	form := Host{Name: "db", Host: "10.0.0.6", User: "u", PasswordMode: PasswordAsk, Rev: h.Rev}
	got, err := s.Update(h.ID, form)
	if err != nil || got.Gateway != "bastion" || got.Host != "10.0.0.6" {
		t.Fatalf("after a form save: %+v, %v", got, err)
	}
	form = Host{Name: "db", Host: "10.0.0.6", User: "u", PasswordMode: PasswordAsk, Jump: "gw"}
	if got, err = s.Update(h.ID, form); err != nil || got.Gateway != "" || got.Jump != "gw" {
		t.Fatalf("jump hosts did not replace the gateway: %+v, %v", got, err)
	}
	if got, err = s.SetGateway(h.ID, "bastion"); err == nil {
		t.Errorf("a gateway was set on a host with jump hosts: %+v", got)
	}
	if _, err := s.Update(h.ID, Host{Name: "db", Host: "10.0.0.6", User: "u", PasswordMode: PasswordAsk}); err != nil {
		t.Fatal(err)
	}
	if got, err = s.SetGateway(h.ID, "bastion"); err != nil || got.Gateway != "bastion" {
		t.Fatalf("set: %+v, %v", got, err)
	}
	if got, err = s.SetGateway(h.ID, ""); err != nil || got.Gateway != "" {
		t.Fatalf("remove: %+v, %v", got, err)
	}
}

// one Host kept in memory, as the app does, follows the network: down
// directly goes through the gateway, answering again goes direct
func TestGatewayCheckedOnEveryConnect(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	h := Host{Name: "db", Host: "127.0.0.1", Port: port, User: "u", PasswordMode: PasswordAsk, Gateway: "ops@gw"}
	if _, err := s.ConnectArgs(&h); err != nil || h.Via() != "ops@gw" {
		t.Fatalf("down directly: via %q, %v", h.Via(), err)
	}
	l, err = net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Skip("the port was taken meanwhile:", err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-test\r\n"))
			c.Close()
		}
	}()
	if _, err := s.ConnectArgs(&h); err != nil || h.Via() != "" {
		t.Fatalf("answering again: via %q, %v", h.Via(), err)
	}
}

// DirectArgs gives the direct way at once, a host that is down is not
// waited on
func TestDirectArgsSkipsTheCheck(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	h := Host{Name: "db", Host: "127.0.0.1", Port: closedPort(t), User: "u", PasswordMode: PasswordAsk, Gateway: "ops@gw"}
	h.route = "stale"
	args, err := s.DirectArgs(&h)
	if err != nil || h.Via() != "" || strings.Contains(strings.Join(args, " "), "-J") {
		t.Fatalf("DirectArgs went through the gateway: %v, %v", args, err)
	}
}

// a host from another device with both jump hosts and a gateway is taken
// with the jump hosts, not refused on every sync
func TestImportDropsGatewayOfJumpHost(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	in := Host{ID: "0123456789abcdef0123456789abcdef", Name: "db", Host: "10.0.0.5", Port: 22, User: "u", PasswordMode: PasswordAsk, Jump: "gw", Gateway: "gw2"}
	got, err := s.Import(in)
	if err != nil || got.Jump != "gw" || got.Gateway != "" {
		t.Fatalf("import: %+v, %v", got, err)
	}
}
