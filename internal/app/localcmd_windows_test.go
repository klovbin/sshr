package app

import "testing"

// TestShellCmdLine checks that a command with quotes reaches cmd.exe as it
// was typed, not escaped as \" (#289)
func TestShellCmdLine(t *testing.T) {
	got := shellCmdLine(`"C:\Program Files\VPN\vpn.exe" up`)
	if got != `cmd /S /C ""C:\Program Files\VPN\vpn.exe" up"` {
		t.Fatalf("cmd line %s", got)
	}
}
