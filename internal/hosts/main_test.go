package hosts

import (
	"os"
	"testing"
)

// TestMain points HOME at a folder of the run, no test of the hosts reaches
// the real ~/.sshr
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "sshr-hosts-test-")
	if err != nil {
		panic(err)
	}
	os.Setenv("HOME", home)
	os.Setenv("USERPROFILE", home)
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}
