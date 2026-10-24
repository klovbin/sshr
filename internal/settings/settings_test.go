package settings

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"sshr.dev/internal/record"
)

func TestSaveSettingsKeepsAChangeSavedMeanwhile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	app, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// another process saves reuse after the app loaded its settings
	other, _ := Load()
	other.Reuse = true
	if err := Save(other); err != nil {
		t.Fatal(err)
	}
	app.Mosh = true
	if err := Save(app); err != nil {
		t.Fatal(err)
	}
	got, _ := Load()
	if !got.Mosh || !got.Reuse {
		t.Fatalf("mosh %v reuse %v, want both on", got.Mosh, got.Reuse)
	}
	// the other process turns mosh off again, the next save of the app
	// changes another field and must not bring its old mosh back
	other, _ = Load()
	other.Mosh = false
	if err := Save(other); err != nil {
		t.Fatal(err)
	}
	app.HealthCheck = true
	if err := Save(app); err != nil {
		t.Fatal(err)
	}
	if got, _ = Load(); got.Mosh || !got.Reuse || !got.HealthCheck {
		t.Fatalf("mosh %v reuse %v health %v, want off, on, on", got.Mosh, got.Reuse, got.HealthCheck)
	}
}

func TestSaveSettingsBuiltFromScratchWritesAll(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	st, _ := Load()
	st.Reuse = true
	if err := Save(st); err != nil {
		t.Fatal(err)
	}
	if err := Save(Settings{Lang: "en"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := Load(); got.Reuse || got.Lang != "en" {
		t.Fatalf("a value built from scratch did not replace the file: %+v", got)
	}
	// a damaged file is replaced by what the holder has
	path := filepath.Join(home, ".sshr", "settings.json")
	os.WriteFile(path, []byte("{"), 0o600)
	st.Mosh = true
	if err := Save(st); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(); err != nil || !got.Mosh || !got.Reuse {
		t.Fatalf("after a damaged file: %+v, %v", got, err)
	}
}

func TestSaveSettingsKeepsAChangeInsideAList(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	st, _ := Load()
	st.AddOPAccount("acc1", "")
	if err := Save(st); err != nil {
		t.Fatal(err)
	}
	st, _ = Load()
	// the email of a linked account is set in place, inside the slice
	st.AddOPAccount("acc1", "me@example.com")
	if err := Save(st); err != nil {
		t.Fatal(err)
	}
	got, _ := Load()
	if len(got.OPAccounts) != 1 || got.OPAccounts[0].Email != "me@example.com" {
		t.Fatalf("accounts after save: %+v", got.OPAccounts)
	}
}

// a new list or map in Settings must be copied by cloneSettings, or a change
// made inside it in place is never saved
func TestCloneSettingsCoversEveryList(t *testing.T) {
	typ := reflect.TypeOf(Settings{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		if k := f.Type.Kind(); (k == reflect.Slice || k == reflect.Map || k == reflect.Pointer) && f.Name != "OPAccounts" && f.Name != "CommandHosts" && f.Name != "HostCommands" {
			t.Errorf("Settings.%s is a %s, copy it in cloneSettings and list it here", f.Name, k)
		}
	}
}

func TestAnEmptyAccountListIsNoChange(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	path := filepath.Join(home, ".sshr", "settings.json")
	os.MkdirAll(filepath.Dir(path), 0o700)
	os.WriteFile(path, []byte(`{"lang":"en","op_accounts":[]}`), 0o600)
	app, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// another process links an account meanwhile
	other, _ := Load()
	other.AddOPAccount("acc1", "me@example.com")
	other.AddOPAccount("acc2", "work@example.com")
	if err := Save(other); err != nil {
		t.Fatal(err)
	}
	app.Mosh = true
	if err := Save(app); err != nil {
		t.Fatal(err)
	}
	if got, _ := Load(); len(got.OPAccounts) != 2 || !got.Mosh {
		t.Fatalf("accounts %+v mosh %v, want both accounts kept and mosh on", got.OPAccounts, got.Mosh)
	}
}

// a key a newer sshr wrote into settings.json survives a save of this one,
// a settings file of a newer format is not written (#97)
func TestSettingsKeepKeysItDoesNotKnow(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	path, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte(`{"lang":"en","future":{"x":1}}`), 0o600)
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	s.Mosh = true
	if err := Save(s); err != nil {
		t.Fatal(err)
	}
	if err := Save(Settings{Lang: "ru"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	var m map[string]json.RawMessage
	json.Unmarshal(b, &m)
	if string(m["future"]) != `{"x":1}` || string(m["lang"]) != `"ru"` {
		t.Fatalf("settings.json: %s", b)
	}
	os.WriteFile(path, []byte(`{"lang":"en","version":5}`), 0o600)
	if err := Save(Settings{Lang: "ru"}); !errors.Is(err, record.ErrNewerFormat) {
		t.Errorf("a newer settings file was written over: %v", err)
	}
	// a newer format that changed the type of a known field reads as newer,
	// not as damaged, and is not replaced (#160)
	newer := `{"lang":"en","version":2,"op_accounts":{"changed":true}}`
	os.WriteFile(path, []byte(newer), 0o600)
	if st, err := Load(); err != nil || st.Lang != "en" {
		t.Errorf("a newer file does not read: %v %+v", err, st)
	}
	if err := Save(Settings{Lang: "ru"}); !errors.Is(err, record.ErrNewerFormat) {
		t.Errorf("a newer file with a changed field was written over: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != newer {
		t.Errorf("settings.json changed: %s", b)
	}
}

// two processes changing the command list keep each other's changes, a
// denial is not undone by an allow of another host (#218)
func TestCommandHostsMergeByKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	st, _ := Load()
	st.AllowCommands("x", "tx")
	if err := Save(st); err != nil {
		t.Fatal(err)
	}
	p1, _ := Load()
	p2, _ := Load()
	p2.DenyCommands("x")
	if err := Save(p2); err != nil {
		t.Fatal(err)
	}
	p1.AllowCommands("y", "ty")
	if err := Save(p1); err != nil {
		t.Fatal(err)
	}
	got, _ := Load()
	if _, back := got.CommandHosts["x"]; back || got.CommandHosts["y"] != "ty" {
		t.Fatalf("command_hosts %v", got.CommandHosts)
	}
}

func TestHealthEvery(t *testing.T) {
	for in, want := range map[int]time.Duration{0: 5 * time.Minute, 10: time.Minute, 600: 10 * time.Minute} {
		if got := (Settings{HealthInterval: in}).HealthEvery(); got != want {
			t.Errorf("%d: %v", in, got)
		}
	}
}
