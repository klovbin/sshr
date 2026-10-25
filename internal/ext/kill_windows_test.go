//go:build windows

package ext

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCollectKillsTheChildOfACmd checks that an importer that is a .cmd
// starting PowerShell stops as a whole when it prints too much (#326): the
// child keeps appending to a file while it lives, the file must stop
// growing once Collect returns
func TestCollectKillsTheChildOfACmd(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "alive")
	script := filepath.Join(dir, "flood.cmd")
	// a ' in the temp path is doubled inside the PowerShell string
	ps := "while ($true) { [IO.File]::AppendAllText('" + strings.ReplaceAll(marker, "'", "''") + "', 'x'); [Console]::Out.Write('y' * 65536) }"
	body := "@echo off\r\npowershell.exe -NoProfile -NonInteractive -Command \"" + ps + "\"\r\n"
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := Collect(exec.Command(script))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "8 MiB") {
			t.Fatalf("Collect: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Collect did not return")
	}
	size := func() int64 {
		fi, err := os.Stat(marker)
		if err != nil {
			return -1
		}
		return fi.Size()
	}
	time.Sleep(time.Second)
	before := size()
	if before < 0 {
		t.Fatal("the PowerShell child never ran")
	}
	time.Sleep(2 * time.Second)
	if after := size(); after != before {
		t.Errorf("the PowerShell child still runs, the file grew from %d to %d", before, after)
	}
}
