//go:build windows

package fileio

import (
	"errors"
	"math/rand/v2"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// shareWait is how long a rename or a read waits for another process that
// has the file open, Windows refuses to replace or open a file in that
// moment where Unix lets both go on, a held file is free again within
// milliseconds, but writers that replace one file at once and a scanner
// that opens each new copy can keep one writer losing for longer, a
// lasting denial gives the same error and comes back after the wait
const shareWait = 2 * time.Second

// busyShare tells an error Windows gives for a file another process holds,
// a read without FILE_SHARE_DELETE (Go's os.Open does not set it) blocks a
// rename over the file, and a file being replaced cannot be opened
func busyShare(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return errno == windows.ERROR_ACCESS_DENIED || errno == windows.ERROR_SHARING_VIOLATION
}

// retryShare runs fn until it succeeds, fails another way or shareWait is
// over, the pause grows from 5 to 40 ms with a random part, writers that
// retry in step would meet at the file again and again
func retryShare(fn func() error) error {
	deadline := time.Now().Add(shareWait)
	pause := 5 * time.Millisecond
	for {
		err := fn()
		if err == nil || !busyShare(err) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(pause + rand.N(pause))
		pause = min(2*pause, 40*time.Millisecond)
	}
}

func renameOver(from, to string) error {
	return retryShare(func() error { return os.Rename(from, to) })
}

// ReadFileShared reads a file another sshr process may be replacing with
// WriteFileAtomic at the same moment
func ReadFileShared(path string) ([]byte, error) {
	var data []byte
	err := retryShare(func() error {
		var err error
		data, err = os.ReadFile(path)
		return err
	})
	return data, err
}
