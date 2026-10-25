package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestWriteFileAtomicConcurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host.json")
	var wg sync.WaitGroup
	errs := make(chan error, 400)
	for g := 0; g < 8; g++ {
		data := bytes.Repeat([]byte{byte('a' + g)}, 64<<10)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if err := WriteFileAtomic(path, data, 0o600); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if len(b) != 64<<10 || bytes.Count(b, b[:1]) != len(b) {
		t.Fatal("the file is a mix of two writers")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(left) > 0 {
		t.Fatalf("temp files left: %v", left)
	}
}

func TestSaveSettingsLeavesNoTornFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				st := Settings{OPAccount: strings.Repeat(string(rune('a'+g)), 4096)}
				if err := SaveSettings(st); err != nil {
					t.Error(err)
				}
			}
		}(g)
	}
	// a reader meanwhile never sees a torn file
	done := make(chan struct{})
	torn := 0
	go func() {
		defer close(done)
		for i := 0; i < 300; i++ {
			if st, err := LoadSettings(); err != nil || st.OPAccount != "" && len(st.OPAccount) != 4096 {
				torn++
			}
		}
	}()
	wg.Wait()
	<-done
	if torn > 0 {
		t.Fatalf("%d reads saw a torn settings file", torn)
	}
	st, err := LoadSettings()
	if err != nil || len(st.OPAccount) != 4096 {
		t.Fatalf("settings after concurrent saves: %v len %d", err, len(st.OPAccount))
	}
}
