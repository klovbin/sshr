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
	for _, want := range []string{"--op-password", "--bw-key", "--agent-key", "-J a,b"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("sshr help add lost %s", want)
		}
	}
}
