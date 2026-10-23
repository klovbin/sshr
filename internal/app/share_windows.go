//go:build windows

package app

import (
	"errors"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// shareWait is how long a rename or a read waits for another process that
// has the file open, Windows refuses to replace or open a file in that
// moment where Unix lets both go on
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

func retryShare(fn func() error) error {
	deadline := time.Now().Add(shareWait)
	for {
		err := fn()
		if err == nil || !busyShare(err) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(5 * time.Millisecond)
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
