//go:build darwin

package desktop

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"sshr.dev/assets"
)

// icnsNative builds a proper .icns via iconutil so Finder / 1Password get sharp sizes.
func icnsNative() ([]byte, error) {
	iconutil, err := exec.LookPath("iconutil")
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "sshr-iconset-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	set := filepath.Join(dir, "sshr.iconset")
	if err := os.Mkdir(set, 0o755); err != nil {
		return nil, err
	}

	// name → source PNG size in assets
	files := map[string]int{
		"icon_16x16.png":      16,
		"icon_16x16@2x.png":   32,
		"icon_32x32.png":      32,
		"icon_32x32@2x.png":   64,
		"icon_128x128.png":    128,
		"icon_128x128@2x.png": 256,
		"icon_256x256.png":    256,
		"icon_256x256@2x.png": 512,
		"icon_512x512.png":    512,
		"icon_512x512@2x.png": 1024,
	}
	for name, size := range files {
		png, err := assets.Icons.ReadFile(fmt.Sprintf("icons/sshr-%d.png", size))
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(set, name), png, 0o644); err != nil {
			return nil, err
		}
	}

	out := filepath.Join(dir, "sshr.icns")
	cmd := exec.Command(iconutil, "-c", "icns", set, "-o", out)
	if b, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("iconutil: %v: %s", err, b)
	}
	return os.ReadFile(out)
}
