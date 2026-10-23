package app

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// errLockHeld means another open file holds the lock tryLock asked for
var errLockHeld = errors.New("lock held")

// BusyError means another sshr process holds a lock and did not let go in
// time, PID is that process when it wrote itself into the lock file
type BusyError struct {
	What string
	PID  int
}

func (e *BusyError) Error() string {
	if e.PID > 0 {
		return fmt.Sprintf("another sshr process (pid %d) is %s, try again in a moment", e.PID, e.What)
	}
	return fmt.Sprintf("another sshr process is %s, try again in a moment", e.What)
}

// lockPoll is how often a waiting process tries the lock again
const lockPoll = 50 * time.Millisecond

// WaitLock takes the exclusive lock on path like waitLock, the sync keeps
// one run at a time with it
func WaitLock(path, what string, wait time.Duration) (func(), error) {
	return waitLock(path, what, wait)
}

// waitLock takes the exclusive lock on path, trying again until wait has
// passed, a wait of 0 tries once, the holder writes its pid into the file so
// a process that gives up can name it, what says what the holder is doing
func waitLock(path, what string, wait time.Duration) (func(), error) {
	deadline := time.Now().Add(wait)
	for {
		f, unlock, err := tryLock(path)
		if err == nil {
			if f.Truncate(0) == nil {
				f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
			}
			return unlock, nil
		}
		if !errors.Is(err, errLockHeld) {
			return nil, err
		}
		if !time.Now().Before(deadline) {
			pid := 0
			if b, err := os.ReadFile(path); err == nil {
				pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
			}
			return nil, &BusyError{What: what, PID: pid}
		}
		time.Sleep(lockPoll)
	}
}
