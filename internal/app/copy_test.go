package app

import (
	"runtime"
	"strings"
	"testing"
)

func TestCopyArgs(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	h := &Host{ID: "a", Name: "web", Host: "10.0.0.5", User: "deploy", Port: 2222, Key: "/k/id"}
	got, err := s.CopyArgs(h, true, false, []string{"a.txt", "dir"}, "/srv")
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Join(got, " ")
	if !strings.Contains(line, "-P 2222") || strings.Contains(line, "-p ") || !strings.HasSuffix(line, "-r -- a.txt dir deploy@10.0.0.5:/srv") {
		t.Fatalf("send = %s", line)
	}
	h6 := &Host{ID: "b", Host: "::1", User: "u", Port: 22}
	got, _ = s.CopyArgs(h6, false, true, []string{"/var/log/x"}, ".")
	if line = strings.Join(got, " "); !strings.HasSuffix(line, "-O -r -- u@[::1]:/var/log/x .") {
		t.Fatalf("get = %s", line)
	}
}

func TestCopyLocalPathWithColon(t *testing.T) {
	cases := map[string]string{
		"report:v2.txt":     "./report:v2.txt",
		"dir/report:v2.txt": "dir/report:v2.txt",
		"plain.txt":         "plain.txt",
		"./a:b":             "./a:b",
	}
	if runtime.GOOS != "windows" {
		cases["/tmp/a:b"] = "/tmp/a:b"
	} else {
		cases[`C:\tmp\a`] = `C:\tmp\a`
	}
	for in, want := range cases {
		if got := localSpec(in); got != want {
			t.Errorf("localSpec(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCopyArgsLocalColon(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	h := &Host{ID: "a", Name: "web", Host: "10.0.0.5", User: "deploy", Port: 22}
	args, err := s.CopyArgs(h, true, false, []string{"report:v2.txt"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(args[len(args)-2:], " "); got != "./report:v2.txt deploy@10.0.0.5:" {
		t.Errorf("send = %q", got)
	}
	args, err = s.CopyArgs(h, false, false, []string{"f"}, "backup:old")
	if err != nil {
		t.Fatal(err)
	}
	if got := args[len(args)-1]; got != "./backup:old" {
		t.Errorf("get destination = %q", got)
	}
}

func TestCopyArgsMore(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	// get with several sources, each one remote
	h := &Host{ID: "a", Name: "web", Host: "10.0.0.5", User: "u", Port: 22}
	got, err := s.CopyArgs(h, false, false, []string{"/a", "/b"}, "out")
	if err != nil {
		t.Fatal(err)
	}
	if line := strings.Join(got, " "); !strings.HasSuffix(line, "-- u@10.0.0.5:/a u@10.0.0.5:/b out") {
		t.Errorf("get two = %s", line)
	}
	// only a -p element becomes -P, a ProxyCommand that holds " -p " stays
	bastion, err := s.Add(Host{Name: "bastion", Host: "10.0.0.9", User: "j", Port: 2200, PasswordMode: PasswordSaved, Password: "x"})
	if err != nil {
		t.Skip("no keychain for a saved password here:", err)
	}
	inner := &Host{ID: "c", Name: "inner", Host: "10.0.0.6", User: "u", Port: 2222, Jump: bastion.Name}
	got, err = s.CopyArgs(inner, true, false, []string{"f"}, "/t")
	if err != nil {
		t.Fatal(err)
	}
	for i, a := range got {
		if a == "-p" {
			t.Errorf("a -p element is left at %d: %q", i, got)
		}
		if strings.HasPrefix(a, "ProxyCommand=") && strings.Contains(a, " -P ") {
			t.Errorf("the ProxyCommand was rewritten: %s", a)
		}
	}
	if line := strings.Join(got, " "); !strings.Contains(line, "-P 2222") {
		t.Errorf("port of the target = %s", line)
	}
}
