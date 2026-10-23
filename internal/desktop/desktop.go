// Package desktop adds sshr to the application menu with its icon, on
// Linux a .desktop entry and icons in the hicolor theme, on macOS an app
// bundle in ~/Applications
package desktop

import (
	"fmt"
	"os"
	"path/filepath"

	"sshr.dev/internal/fileio"
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
	if err := fileio.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("%s: %v", path, err)
	}
	return nil
}
