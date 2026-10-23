package ext

import (
	"strings"
	"testing"
)

const goodManifest = `{"protocol":1,"name":"hello","version":"0.1.0","description":"demo",
"command":{"linux":["./hello.sh","--x"],"default":["./hello"]},"kinds":["command","import"]}`

func TestParseManifestAccepts(t *testing.T) {
	m, err := ParseManifest([]byte(goodManifest))
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "hello" || !m.Has(KindImport) || !m.Has(KindCommand) {
		t.Fatalf("parsed %+v", m)
	}
	if argv, _ := m.Argv("linux"); strings.Join(argv, " ") != "./hello.sh --x" {
		t.Errorf("linux argv = %v", argv)
	}
	if argv, _ := m.Argv("windows"); strings.Join(argv, " ") != "./hello" {
		t.Errorf("windows falls back to default, got %v", argv)
	}
}

func TestParseManifestRefuses(t *testing.T) {
	cases := map[string]string{
		"another protocol":     `{"protocol":2,"name":"a","version":"1","command":{"default":["./a"]},"kinds":["command"]}`,
		"a path as name":       `{"protocol":1,"name":"../a","version":"1","command":{"default":["./a"]},"kinds":["command"]}`,
		"an upper case name":   `{"protocol":1,"name":"Hello","version":"1","command":{"default":["./a"]},"kinds":["command"]}`,
		"no version":           `{"protocol":1,"name":"a","command":{"default":["./a"]},"kinds":["command"]}`,
		"no kinds":             `{"protocol":1,"name":"a","version":"1","command":{"default":["./a"]},"kinds":[]}`,
		"an unknown kind":      `{"protocol":1,"name":"a","version":"1","command":{"default":["./a"]},"kinds":["hook"]}`,
		"no command":           `{"protocol":1,"name":"a","version":"1","command":{},"kinds":["command"]}`,
		"an absolute program":  `{"protocol":1,"name":"a","version":"1","command":{"default":["/bin/sh","-c","x"]},"kinds":["command"]}`,
		"a program outside":    `{"protocol":1,"name":"a","version":"1","command":{"default":["../../bin/x"]},"kinds":["command"]}`,
		"an option as program": `{"protocol":1,"name":"a","version":"1","command":{"default":["-c"]},"kinds":["command"]}`,
		"a backslash":          `{"protocol":1,"name":"a","version":"1","command":{"default":["..\\x"]},"kinds":["command"]}`,
		"an unknown field":     `{"protocol":1,"name":"a","version":"1","command":{"default":["./a"]},"kinds":["command"],"sha256":"x"}`,
		"a program in .git":    `{"protocol":1,"name":"a","version":"1","command":{"default":[".git/run"]},"kinds":["command"]}`,
		"not JSON":             `name: a`,
	}
	for name, in := range cases {
		if _, err := ParseManifest([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestArgvWithoutCommandForTheSystem(t *testing.T) {
	m, err := ParseManifest([]byte(`{"protocol":1,"name":"a","version":"1","command":{"linux":["./a"]},"kinds":["command"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Argv("windows"); err == nil {
		t.Error("an extension with a command for linux only has one for windows")
	}
}
