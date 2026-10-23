package fileio

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLockHelper is not a test, the tests below start the test binary
// again with SSHR_LOCK_HELPER set to run it as a second sshr process
func TestLockHelper(t *testing.T) {
	switch os.Getenv("SSHR_LOCK_HELPER") {
	case "hold":
		unlock, err := waitLock(os.Getenv("SSHR_LOCK_PATH"), "testing", time.Second)
		if err != nil {
			fmt.Println("error", err)
			os.Exit(1)
		}
		fmt.Println("locked")
		io.Copy(io.Discard, os.Stdin)
		unlock()
		os.Exit(0)
	}
}

func helper(t *testing.T, env ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockHelper$")
	cmd.Env = append(os.Environ(), env...)
	return cmd
}

func TestWaitLockBusyNamesHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")
	cmd := helper(t, "SSHR_LOCK_HELPER=hold", "SSHR_LOCK_PATH="+path)
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	defer in.Close()
	line, _ := bufio.NewReader(out).ReadString('\n')
	if strings.TrimSpace(line) != "locked" {
		t.Fatalf("helper said %q", line)
	}
	start := time.Now()
	_, err := waitLock(path, "saving hosts", 200*time.Millisecond)
	var busy *BusyError
	if !errors.As(err, &busy) {
		t.Fatalf("want BusyError, got %v", err)
	}
	if busy.PID != cmd.Process.Pid {
		t.Errorf("busy names pid %d, the holder is %d", busy.PID, cmd.Process.Pid)
	}
	if !strings.Contains(err.Error(), "saving hosts") {
		t.Errorf("message %q does not say what the holder does", err)
	}
	if d := time.Since(start); d < 200*time.Millisecond || d > 5*time.Second {
		t.Errorf("gave up after %v, want about 200ms", d)
	}
	in.Close()
	unlock, err := waitLock(path, "saving hosts", 10*time.Second)
	if err != nil {
		t.Fatalf("lock not free after the holder let go: %v", err)
	}
	unlock()
}

func TestWaitLockSameProcessExcludes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")
	unlock, err := waitLock(path, "testing", 0)
	if err != nil {
		t.Fatal(err)
	}
	// a second take in the same process must not pass, flock and
	// LockFileEx belong to the open file, a lock per process would let
	// two goroutines of the app write at once
	if _, err := waitLock(path, "testing", 0); err == nil {
		t.Fatal("a second lock in the same process was granted")
	}
	unlock()
	unlock2, err := waitLock(path, "testing", 0)
	if err != nil {
		t.Fatalf("lock not free after unlock: %v", err)
	}
	unlock2()
}
