//go:build linux

package app

import (
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// TestHarden runs Harden in a child, the test process keeps its own
// state: the child is not dumpable and has no core limit, with
// SSHR_ALLOW_DEBUG it stays as it was
func TestHarden(t *testing.T) {
	if os.Getenv("SSHR_HARDEN_CHILD") == "1" {
		if err := Harden(); err != nil {
			t.Fatal(err)
		}
		dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		var lim unix.Rlimit
		unix.Getrlimit(unix.RLIMIT_CORE, &lim)
		want := os.Getenv("SSHR_ALLOW_DEBUG") != "1"
		if err != nil || (dumpable == 0) != want || (lim.Cur == 0 && lim.Max == 0) != want {
			t.Fatalf("dumpable %d %v, core limit %+v, hardened wanted %v", dumpable, err, lim, want)
		}
		return
	}
	for _, allow := range []string{"", "1"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHarden$", "-test.count=1")
		cmd.Env = append(os.Environ(), "SSHR_HARDEN_CHILD=1", "SSHR_ALLOW_DEBUG="+allow)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("SSHR_ALLOW_DEBUG=%q: %v\n%s", allow, err, out)
		}
	}
}
