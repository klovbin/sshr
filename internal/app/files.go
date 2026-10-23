package app

import (
	"os"
	"time"

	"sshr.dev/internal/fileio"
)

// The file helpers of sshr live in internal/fileio, the sync server uses
// them without the core, these names keep the callers of app as they are

// BusyError means another sshr process holds a lock and did not let go
type BusyError = fileio.BusyError

// WriteFileAtomic writes path through a temp file of its own and a rename
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	return fileio.WriteFile(path, data, mode)
}

// ReadFileShared reads a file another sshr process may be replacing
func ReadFileShared(path string) ([]byte, error) { return fileio.ReadFileShared(path) }

// LockFile holds an exclusive lock on path until the returned func runs
func LockFile(path string) (func(), error) { return fileio.LockFile(path) }

// WaitLock takes the exclusive lock on path, waiting up to wait
func WaitLock(path, what string, wait time.Duration) (func(), error) {
	return fileio.WaitLock(path, what, wait)
}

func lockFile(path string) (func(), error) { return fileio.LockFile(path) }

func waitLock(path, what string, wait time.Duration) (func(), error) {
	return fileio.WaitLock(path, what, wait)
}
