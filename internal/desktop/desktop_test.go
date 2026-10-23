//go:build linux

package desktop

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallLinux(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dir)
	t.Setenv("PATH", "")
	entry, err := Install()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(entry)
	if !strings.Contains(string(b), "\nIcon=sshr\n") || !strings.Contains(string(b), "\nExec=\"/") {
		t.Fatalf("entry:\n%s", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "icons/hicolor/256x256/apps/sshr.png")); err != nil {
		t.Fatal(err)
	}
	if err := Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(entry); !os.IsNotExist(err) {
		t.Fatal("entry left after Remove")
	}
}

func TestExecQuote(t *testing.T) {
	if got, want := execQuote("/a b%/$x\"`\\"), `"/a b%%/\\$x\\"\\`+"`"+`\\\\"`; got != want {
		t.Fatal(got)
	}
}

func TestICNS(t *testing.T) {
	b, err := icns()
	if err != nil {
		t.Fatal(err)
	}
	if string(b[:4]) != "icns" || int(b[4])<<24|int(b[5])<<16|int(b[6])<<8|int(b[7]) != len(b) {
		t.Fatal("bad icns header")
	}
	// SSHR_ICNS_OUT=<dir> keeps the file for a look with other tools
	if dir := os.Getenv("SSHR_ICNS_OUT"); dir != "" {
		os.WriteFile(filepath.Join(dir, "sshr.icns"), b, 0o644)
	}
}
