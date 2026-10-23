package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestUsageIsShort(t *testing.T) {
	var b bytes.Buffer
	writeUsage(&b)
	lines := strings.Count(b.String(), "\n")
	if lines > len(commands)+12 {
		t.Errorf("the overview has %d lines", lines)
	}
	for _, c := range commands {
		if !strings.Contains(b.String(), "  "+c.name+" ") {
			t.Errorf("%s is missing from the overview", c.name)
		}
	}
}

func TestCommandHelp(t *testing.T) {
	for alias, name := range map[string]string{"ls": "list", "import-ssh-config": "import", "export-ssh-config": "export"} {
		if c := findCommand(alias); c == nil || c.name != name {
			t.Fatalf("%s = %+v", alias, c)
		}
	}
	var b bytes.Buffer
	writeCommandHelp(&b, findCommand("add"))
	for _, want := range []string{"--op-password", "--bw-key", "--agent-key", "--jump <a,b>", "--op-vault"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("sshr help add lost %s", want)
		}
	}
}

func TestClosest(t *testing.T) {
	names := []string{"tunnel", "tag", "connect", "export", "list", "ls"}
	for in, want := range map[string]string{"tunel": "tunnel", "conect": "connect", "exprt": "export", "lsit": "list", "exp": "export"} {
		if got := closest(in, names); len(got) == 0 || got[0] != want {
			t.Errorf("closest(%q) = %v, want %s first", in, got, want)
		}
	}
	if got := closest("zzzzzz", names); len(got) != 0 {
		t.Errorf("closest of nothing like = %v", got)
	}
}
