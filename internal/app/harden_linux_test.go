//go:build linux

package app

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// TestHarden runs Harden in a child, the test process keeps its own
// state: the child is not dumpable and its soft core limit is 0 while the
// hard one stays, with SSHR_ALLOW_DEBUG it stays as it was
func TestHarden(t *testing.T) {
	if os.Getenv("SSHR_HARDEN_CHILD") == "1" {
		var before, after unix.Rlimit
		unix.Getrlimit(unix.RLIMIT_CORE, &before)
		if err := Harden(); err != nil && !(os.Getenv("SSHR_ALLOW_DEBUG") == "1" && errors.Is(err, ErrHardenSkipped)) {
			t.Fatal(err)
		}
		dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		unix.Getrlimit(unix.RLIMIT_CORE, &after)
		want := before
		if os.Getenv("SSHR_ALLOW_DEBUG") != "1" {
			// only the soft limit goes to 0, the hard one is left for the
			// programs sshr starts (#342), compared with the limit the child
			// started with, a limit of 0 already is no proof (#343)
			want.Cur = 0
			if err != nil || dumpable != 0 || after != want {
				t.Fatalf("dumpable %d %v, core limit %+v, want %+v", dumpable, err, after, want)
			}
			return
		}
		if err != nil || dumpable != 1 || after != want {
			t.Fatalf("with SSHR_ALLOW_DEBUG: dumpable %d %v, core limit %+v, want %+v", dumpable, err, after, want)
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
