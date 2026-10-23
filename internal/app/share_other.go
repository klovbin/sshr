//go:build !windows

package app

import "os"

// renameOver replaces to with from, a rename on Unix never waits for a
// process that has the file open
func renameOver(from, to string) error { return os.Rename(from, to) }

// ReadFileShared reads a file another sshr process may be replacing with
// WriteFileAtomic at the same moment, on Unix a plain read sees the old or
// the new file
func ReadFileShared(path string) ([]byte, error) { return os.ReadFile(path) }
