package hosts

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ExpandHome turns ~/… into an absolute path under the user home.
func ExpandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// CheckPrivateKey accepts a small file with a "PRIVATE KEY" header (OpenSSH
// and PEM), so a public key or a wrong path fails at save, not later at connect.
func CheckPrivateKey(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("key file not found: %s", path)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 16384 {
		return fmt.Errorf("not a private key file: %s", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !strings.Contains(string(b), "PRIVATE KEY") {
		if strings.HasSuffix(path, ".pub") {
			return fmt.Errorf("%s is a public key; pass the file without .pub", path)
		}
		return fmt.Errorf("not a private key file: %s", path)
	}
	return nil
}
