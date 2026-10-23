//go:build !windows

package fileio

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// lockFile holds an exclusive lock on path until the returned func runs
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
	}, nil
}

// tryLock is lockFile that gives up at once with errLockHeld when another
// open file holds the lock, f stays open while the lock is held
func tryLock(path string) (*os.File, func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, nil, errLockHeld
		}
		return nil, nil, err
	}
	return f, func() {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
	}, nil
}
