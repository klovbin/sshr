package app

import (
	"runtime"
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
	want := " __proxy 'bastion,gw' %h %p"
	if runtime.GOOS == "windows" {
		want = " __proxy bastion,gw %h %p"
	}
	if line := strings.Join(args, " "); !strings.Contains(line, want) {
		t.Fatalf("ProxyCommand = %s", line)
	}
}

// the golden lines pin the spelling per target: the POSIX lines byte for
// byte, the windows lines what the windows target emits
func TestProxyCommandGolden(t *testing.T) {
	for _, tc := range []struct{ goos, exe, chain, want string }{
		{"linux", "/usr/local/bin/sshr", "bastion", `"/usr/local/bin/sshr" __proxy 'bastion' %h %p`},
		{"linux", "/opt/my tools/sshr", "bastion,gw", `"/opt/my tools/sshr" __proxy 'bastion,gw' %h %p`},
		{"linux", "/usr/local/bin/sshr", "ops@gw:2222", `"/usr/local/bin/sshr" __proxy 'ops@gw:2222' %h %p`},
		{"linux", "/usr/local/bin/sshr", "u@[::1]:22", `"/usr/local/bin/sshr" __proxy 'u@[::1]:22' %h %p`},
		{"linux", "/opt/100%/sshr", "bastion", `"/opt/100%%/sshr" __proxy 'bastion' %h %p`},
		{"windows", `C:\Users\u\sshr.exe`, "bastion", `"C:\Users\u\sshr.exe" __proxy bastion %h %p`},
		{"windows", `C:\Users\u\sshr.exe`, "ops@gw:2222", `"C:\Users\u\sshr.exe" __proxy ops@gw:2222 %h %p`},
		{"windows", `C:\100%\sshr.exe`, "bastion", `"C:\100%%\sshr.exe" __proxy bastion %h %p`},
	} {
		if got := proxyCommand(tc.goos, tc.exe, tc.chain); got != tc.want {
			t.Errorf("proxyCommand(%q, %q, %q):\n got %s\nwant %s", tc.goos, tc.exe, tc.chain, got, tc.want)
		}
	}
}

// on windows the exe carries its backslashes as written and the hops
// arrive as themselves: no single quote anywhere in the line, the exe
// segment the shell reads is the executable path, and every hop in the
// chain the line carries parses back to a hop
func TestProxyCommandWindowsQuoting(t *testing.T) {
	for _, tc := range []struct{ exe, chain string }{
		{`C:\Users\u\sshr.exe`, "bastion"},
		{`C:\Users\u\sshr.exe`, "bastion,gw"},
		{`C:\Users\u\sshr.exe`, "ops@gw:2222"},
		{`C:\Users\u\sshr.exe`, "u@[::1]:22"},
		{`C:\Program Files\sshr\sshr.exe`, "ops@gw:2222"},
	} {
		line := proxyCommand("windows", tc.exe, tc.chain)
		if strings.Contains(line, "'") {
			t.Errorf("chain %s: a single quote reaches the command line: %s", tc.chain, line)
		}
		if strings.Contains(line, `\\`) {
			t.Errorf("chain %s: a doubled backslash reaches the command line: %s", tc.chain, line)
		}
		exe, rest, ok := splitExeSegment(line)
		if !ok {
			t.Fatalf("chain %s: no exe segment in %s", tc.chain, line)
		}
		if exe != tc.exe {
			t.Errorf("chain %s: the exe segment is %q, not the executable path %q: %s", tc.chain, exe, tc.exe, line)
		}
		fields := strings.Fields(rest)
		if len(fields) != 4 || fields[0] != ProxyCommandName || fields[2] != "%h" || fields[3] != "%p" {
			t.Fatalf("chain %s: unexpected command after the exe: %s", tc.chain, rest)
		}
		for _, part := range SplitJump(fields[1]) {
			if _, err := ParseHop(part); err != nil {
				t.Errorf("chain %s: hop %q does not arrive parseable: %v", tc.chain, part, err)
			}
		}
	}
}

// splitExeSegment takes the quoted or bare exe segment off the front of a
// ProxyCommand line and returns the rest of the line
func splitExeSegment(line string) (exe, rest string, ok bool) {
	if strings.HasPrefix(line, `"`) {
		end := strings.Index(line[1:], `"`)
		if end < 0 {
			return "", "", false
		}
		return line[1 : 1+end], strings.TrimPrefix(line[end+2:], " "), true
	}
	i := strings.IndexByte(line, ' ')
	if i < 0 {
		return "", "", false
	}
	return line[:i], line[i+1:], true
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
