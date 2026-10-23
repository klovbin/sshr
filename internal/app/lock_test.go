package app

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
	case "count":
		s := &Store{Dir: os.Getenv("SSHR_LOCK_DIR")}
		n, _ := strconv.Atoi(os.Getenv("SSHR_LOCK_N"))
		for i := 0; i < n; i++ {
			if err := bumpPort(s, os.Getenv("SSHR_LOCK_ID")); err != nil {
				fmt.Println("error", err)
				os.Exit(1)
			}
		}
		os.Exit(0)
	}
}

func helper(t *testing.T, env ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockHelper$")
	cmd.Env = append(os.Environ(), env...)
	return cmd
}

// bumpPort reads a host, adds one to its port and saves it in one locked
// step, the port is a counter that loses a step when two writers interleave
func bumpPort(s *Store, id string) error {
	return s.Locked(func(tx *Store) error {
		h, err := tx.Find(id)
		if err != nil {
			return err
		}
		h.Port++
		_, err = tx.Update(id, *h)
		return err
	})
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

func TestStoreLockedKeepsEveryUpdate(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Dir: dir}
	h, err := s.Add(Host{Name: "counter", Host: "example.com", User: "u", Port: 1})
	if err != nil {
		t.Fatal(err)
	}
	const procs, goroutines, n = 3, 3, 15
	var wg sync.WaitGroup
	errs := make(chan error, procs+goroutines)
	for i := 0; i < procs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := helper(t, "SSHR_LOCK_HELPER=count", "SSHR_LOCK_DIR="+dir, "SSHR_LOCK_ID="+h.ID, "SSHR_LOCK_N="+strconv.Itoa(n)).CombinedOutput()
			if err != nil {
				errs <- fmt.Errorf("helper: %v %s", err, out)
			}
		}()
	}
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < n; j++ {
				if err := bumpPort(s, h.ID); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	got, err := s.Find(h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := 1 + (procs+goroutines)*n; got.Port != want {
		t.Errorf("port is %d after %d locked steps from 1, want %d, some updates were lost", got.Port, (procs+goroutines)*n, want)
	}
}

func TestStoreLockedNestedCallsDoNotWait(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	done := make(chan error, 1)
	go func() {
		done <- s.Locked(func(tx *Store) error {
			h, err := tx.Add(Host{Name: "a", Host: "example.com", User: "u"})
			if err != nil {
				return err
			}
			if _, err := tx.Duplicate(h.ID, "b"); err != nil {
				return err
			}
			return tx.Delete(h.ID)
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a Store method called inside Locked waits for the lock its caller holds")
	}
}
