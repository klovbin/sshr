// Package fileio holds what every sshr process does with its files: a
// write that a reader never sees half of, a lock between processes, a read
// that waits out a Windows rename, it imports nothing of sshr, so the sync
// server and small tools use it without the core
package fileio

import (
	"os"
	"path/filepath"
	"runtime"
)

// WriteFile writes through a temporary file of its own next to path,
// a reader never sees half of it and two writers never share a temp file
func WriteFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	// the data reaches the disk before the rename does, a power loss
	// leaves the old file or the new one, never an empty one
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, mode)
	}
	if err == nil {
		// Windows refuses the rename for a moment while another process
		// reads the file, renameOver waits that out
		err = renameOver(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

// syncDir makes a rename in dir durable, Windows has no directory sync and
// commits the rename itself
func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}
