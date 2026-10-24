package sshcmd

import (
	"strings"
	"testing"
)

// a jump hop from sync or the REST API must not reach the shell that runs
// ProxyCommand or add lines to the ssh config export (#40)
func TestJumpRejectsShellAndConfigInjection(t *testing.T) {
	for _, bad := range []string{
		"j1,a;touch${IFS}/tmp/p",
		"j1,x\nHost=*\nPermitLocalCommand=yes",
		"a|b", "a$(id)", "a`id`", "-oProxyCommand=x", "a b", "a'b", "a%h",
	} {
		if _, err := normalizeJump(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, ok := range []string{"bastion", "ops@gw:2222", "gw,bastion", "u@[::1]:22", "web.prod-1", "0123abcd"} {
		if _, err := normalizeJump(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	s := &Store{Dir: t.TempDir()}
	if _, err := s.Add(Host{Host: "h", User: "u", PasswordMode: PasswordAsk, Jump: "j;id"}); err == nil {
		t.Error("a host with a shell character in its jump was saved")
	}
	// a bad value already on disk is refused at connect too
	if _, err := s.JumpArgs(&Host{Jump: "a\nLocalCommand=id"}); err == nil {
		t.Error("JumpArgs used a bad jump from disk")
	}
}

func TestProxyCommandQuotesHops(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	bastion, err := s.Add(Host{Name: "bastion", Host: "10.0.0.1", User: "u", PasswordMode: PasswordAsk})
	if err != nil {
		t.Fatal(err)
	}
	args, err := s.JumpArgs(&Host{Jump: bastion.Name + ",gw"})
	if err != nil {
		t.Fatal(err)
	}
	if line := strings.Join(args, " "); !strings.Contains(line, " __proxy 'bastion,gw' %h %p") {
		t.Fatalf("ProxyCommand = %s", line)
	}
}

// a plain user@host hop must not see the target's saved password (#43)
func TestSavedPasswordHostAvoidsDashJ(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	plain, _ := s.JumpArgs(&Host{Jump: "ops@gw:2222", PasswordMode: PasswordAsk})
	if strings.Join(plain, " ") != "-J ops@gw:2222" {
		t.Errorf("ask host = %v", plain)
	}
	for _, mode := range []string{PasswordSaved, PasswordOnePassword, PasswordBitwarden} {
		args, err := s.JumpArgs(&Host{Jump: "ops@gw:2222", PasswordMode: mode})
		if err != nil {
			t.Fatal(err)
		}
		if line := strings.Join(args, " "); strings.Contains(line, "-J") || !strings.Contains(line, "ProxyCommand=") {
			t.Errorf("%s host = %s", mode, line)
		}
	}
}

// an address reaches %h in the shell-run ProxyCommand (#44)
func TestAddressRefusesShellCharacters(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	for _, bad := range []string{"a;id", "a$(id)", "a b", "-oProxyCommand=x", "a\nb", "a|b", "a%h"} {
		if _, err := s.Add(Host{Host: bad, User: "u", PasswordMode: PasswordAsk}); err == nil {
			t.Errorf("address %q saved", bad)
		}
	}
	for _, ok := range []string{"web.example.com", "10.0.0.5", "::1", "[fe80::1]", "my_alias", "host-1"} {
		if _, err := s.Add(Host{Host: ok, User: "u", PasswordMode: PasswordAsk}); err != nil {
			t.Errorf("address %q refused: %v", ok, err)
		}
	}
	if _, err := s.ConnectArgs(&Host{Host: "a;id", User: "u", Port: 22}); err == nil {
		t.Error("ConnectArgs used a bad address from disk")
	}
}

// a plain hop must not be offered a key the sshr agent serves for the
// host behind it (#134)
func TestAgentKeyHostAvoidsDashJ(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	for _, mode := range []string{KeyVault, KeyOnePassword, KeyBitwarden} {
		args, err := s.JumpArgs(&Host{Jump: "ops@gw:2222", KeyMode: mode})
		if err != nil {
			t.Fatal(err)
		}
		if line := strings.Join(args, " "); strings.Contains(line, "-J") || !strings.Contains(line, "ProxyCommand=") {
			t.Errorf("%s key host = %v", mode, args)
		}
	}
	if args, _ := s.JumpArgs(&Host{Jump: "ops@gw:2222", Key: "/k"}); strings.Join(args, " ") != "-J ops@gw:2222" {
		t.Errorf("a key file host = %v", args)
	}
}
