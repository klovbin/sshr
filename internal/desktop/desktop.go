// Package desktop adds sshr to the application menu with its icon, on
// Linux a .desktop entry and icons in the hicolor theme, on macOS an app
// bundle in ~/Applications
package desktop

import (
	"fmt"
	"os"
	"path/filepath"
)

// executable is the resolved path of the running sshr, the entry points
// at the real file, not at a link that may go away
func executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return exe, nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// a temp file of its own, two runs at once never share one
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
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("%s: %v", path, err)
	}
	return nil
}
