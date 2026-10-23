package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveSettingsKeepsAChangeSavedMeanwhile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	app, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	// another process saves reuse after the app loaded its settings
	other, _ := LoadSettings()
	other.Reuse = true
	if err := SaveSettings(other); err != nil {
		t.Fatal(err)
	}
	app.Mosh = true
	if err := SaveSettings(app); err != nil {
		t.Fatal(err)
	}
	got, _ := LoadSettings()
	if !got.Mosh || !got.Reuse {
		t.Fatalf("mosh %v reuse %v, want both on", got.Mosh, got.Reuse)
	}
	// the other process turns mosh off again, the next save of the app
	// changes another field and must not bring its old mosh back
	other, _ = LoadSettings()
	other.Mosh = false
	if err := SaveSettings(other); err != nil {
		t.Fatal(err)
	}
	app.HealthCheck = true
	if err := SaveSettings(app); err != nil {
		t.Fatal(err)
	}
	if got, _ = LoadSettings(); got.Mosh || !got.Reuse || !got.HealthCheck {
		t.Fatalf("mosh %v reuse %v health %v, want off, on, on", got.Mosh, got.Reuse, got.HealthCheck)
	}
}

func TestSaveSettingsBuiltFromScratchWritesAll(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	st, _ := LoadSettings()
	st.Reuse = true
	if err := SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	if err := SaveSettings(Settings{Lang: "en"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := LoadSettings(); got.Reuse || got.Lang != "en" {
		t.Fatalf("a value built from scratch did not replace the file: %+v", got)
	}
	// a damaged file is replaced by what the holder has
	path := filepath.Join(home, ".sshr", "settings.json")
	os.WriteFile(path, []byte("{"), 0o600)
	st.Mosh = true
	if err := SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadSettings(); err != nil || !got.Mosh || !got.Reuse {
		t.Fatalf("after a damaged file: %+v, %v", got, err)
	}
}
