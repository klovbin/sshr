package fileio

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// lockOffset is the byte both locks take, far past the pid waitLock writes
// at the start, a Windows lock keeps other processes from reading the bytes
// it covers, LockFile and WaitLock on one path exclude each other
const lockOffset = 1 << 30

// lockFile holds an exclusive lock on path until the returned func runs
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	h := windows.Handle(f.Fd())
	ol := &windows.Overlapped{Offset: lockOffset}
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, ol); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		windows.UnlockFileEx(h, 0, 1, 0, ol)
		f.Close()
	}, nil
}

// tryLock is lockFile that gives up at once with errLockHeld when another
// handle holds the lock, f stays open while the lock is held
func tryLock(path string) (*os.File, func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, nil, err
	}
	h := windows.Handle(f.Fd())
	ol := &windows.Overlapped{Offset: lockOffset}
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol); err != nil {
		f.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
			return nil, nil, errLockHeld
		}
		return nil, nil, err
	}
	return f, func() {
		windows.UnlockFileEx(h, 0, 1, 0, ol)
		f.Close()
	}, nil
}
