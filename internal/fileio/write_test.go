package fileio

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsFileTellsFileFromFolderAndNothing(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	cases := map[string]bool{file: true, dir: false, filepath.Join(dir, "missing"): false}

	for path, want := range cases {
		if got := IsFile(path); got != want {
			t.Errorf("IsFile(%s) = %v, want %v", path, got, want)
		}
	}
}
