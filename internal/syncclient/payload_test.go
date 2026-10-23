package syncclient

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"sshr.dev/internal/app"
)

// The bytes of a payload in today's format, the local change check hashes
// them, a host without new fields must give the same bytes in every later
// build, or every host on every device looks edited at the next sync and
// a remote change becomes a conflict copy (#97)
func TestPayloadBytesStayTheSame(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	h := app.Host{ID: "0123456789abcdef0123456789abcdef", Name: "web", Host: "10.0.0.5", Port: 2222, User: "u", Key: "/k", Jump: "gw", Session: "tmux",
		Forwards: []app.Forward{{Name: "db", Kind: "L", Spec: "5432:localhost:5432"}}, Tags: []string{"prod"}, CreatedAt: now,
		LastConnected: &now, Rev: 3, PasswordRef: "op://x", KeyRef: "op://y"}
	b, err := payloadOf(h)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"host":{"id":"0123456789abcdef0123456789abcdef","name":"web","host":"10.0.0.5","port":2222,"user":"u","key":"/k","jump":"gw","session":"tmux","forwards":[{"name":"db","kind":"L","spec":"5432:localhost:5432"}],"tags":["prod"],"created_at":"2026-10-01T12:00:00Z"}}`
	if string(b) != want {
		t.Fatalf("payload\n got %s\nwant %s", b, want)
	}
}

// Every field of app.Host has a place in sync, a new field fails here
// until it is put in one: synced as it is, stripped by payloadOf, or
// memory only (json:"-", never written)
func TestHostFieldsAreClassified(t *testing.T) {
	classes := map[string]string{
		"ID": "synced", "Name": "synced", "Host": "synced", "Port": "synced", "User": "synced",
		// a key file path and an agent travel, FromOtherDevice keeps the local
		// ones while the destination stays and drops them when it moved (#195)
		"Key": "synced", "Agent": "synced",
		"KeyMode": "synced", "KeyPub": "synced", "PasswordMode": "synced",
		"Jump": "synced", "Gateway": "synced", "Session": "synced", "Forwards": "synced", "Tags": "synced", "CreatedAt": "synced",
		"KeySealed": "stripped", "PasswordSealed": "stripped", "PlainPassword": "stripped",
		"PasswordRef": "stripped", "KeyRef": "stripped", "LastConnected": "stripped", "Rev": "stripped",
		"KeyData": "memory", "KeyPassphrase": "memory", "AgentKey": "memory", "Password": "memory",
	}
	typ := reflect.TypeOf(app.Host{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		class, ok := classes[f.Name]
		if !ok {
			t.Errorf("app.Host.%s has no class, decide whether it syncs, is stripped in payloadOf or is memory only", f.Name)
			continue
		}
		if memory := f.Tag.Get("json") == "-"; memory != (class == "memory") {
			t.Errorf("app.Host.%s is classed %s but its json tag is %q", f.Name, class, f.Tag.Get("json"))
		}
	}
	// the stripped ones are really gone from what syncs
	now := time.Now()
	h := app.Host{ID: "0123456789abcdef0123456789abcdef", Name: "w", Host: "h", User: "u",
		KeySealed: "v1:x", PasswordSealed: "v2:y", PlainPassword: "z", PasswordRef: "op://p", KeyRef: "op://k", Rev: 9, LastConnected: &now}
	b, err := payloadOf(h)
	if err != nil {
		t.Fatal(err)
	}
	for name, class := range classes {
		if class != "stripped" {
			continue
		}
		f, _ := typ.FieldByName(name)
		tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if strings.Contains(string(b), `"`+tag+`"`) {
			t.Errorf("%s (%s) reaches the payload: %s", name, tag, b)
		}
	}
}

// a field of a newer sshr travels with its host and survives an edit on
// another device, a local_ field stays on the device that wrote it (#97)
func TestSyncCarriesUnknownFields(t *testing.T) {
	w := newWorld(t)
	web, _ := w.pair()
	writeRaw(t, w.a.Store, web.ID, func(m map[string]any) {
		m["future"] = map[string]any{"x": 1}
		m["local_secret"] = "only here"
	})
	h, _ := w.a.Store.Find(web.ID)
	h.Port = 2201
	_, err := w.a.Store.Update(web.ID, *h)
	must(t, err)
	must(t, w.a.Push())
	must(t, w.b.Pull())
	onB := readRaw(t, w.b.Store, web.ID)
	if string(onB["future"]) != `{"x":1}` || onB["local_secret"] != nil {
		t.Fatalf("on b: %v", onB)
	}
	hb, _ := w.b.Store.Find(web.ID)
	_, err = w.b.Store.Update(web.ID, app.Host{Name: hb.Name, Host: hb.Host, Port: 2202, User: hb.User, PasswordMode: hb.PasswordMode, Rev: hb.Rev})
	must(t, err)
	must(t, w.b.Push())
	must(t, w.a.Pull())
	onA := readRaw(t, w.a.Store, web.ID)
	if string(onA["future"]) != `{"x":1}` || string(onA["local_secret"]) != `"only here"` || string(onA["port"]) != "2202" {
		t.Fatalf("on a: %v\n%s", onA, w.log.String())
	}
}

func readRaw(t *testing.T, s *app.Store, id string) map[string]json.RawMessage {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.Dir, id+".json"))
	must(t, err)
	var m map[string]json.RawMessage
	must(t, json.Unmarshal(b, &m))
	return m
}

// a host of a newer format is not pushed by a build that cannot write
// it, it may hold fields this build did not decode, the other devices
// keep the version its own device wrote (#164)
func TestSyncDoesNotPushANewerHostFormat(t *testing.T) {
	w := newWorld(t)
	web, _ := w.pair()
	before := readRaw(t, w.b.Store, web.ID)
	writeRaw(t, w.a.Store, web.ID, func(m map[string]any) { m["version"] = 7; m["port"] = "not a number" })
	h, err := w.a.Store.Find(web.ID)
	must(t, err)
	if _, err := payloadOf(*h); !errors.Is(err, app.ErrNewerFormat) {
		t.Fatalf("payloadOf of a newer host: %v", err)
	}
	must(t, w.a.Push())
	if _, ok := w.a.LeftOut[web.ID]; !ok {
		t.Errorf("a did not leave the newer host out: %v", w.a.LeftOut)
	}
	must(t, w.b.Pull())
	if after := readRaw(t, w.b.Store, web.ID); string(after["port"]) != string(before["port"]) {
		t.Fatalf("b got the host a could not read: %v", after)
	}
	if _, err := w.b.Store.Find(web.ID); err != nil {
		t.Fatalf("b lost the host: %v", err)
	}
}

// a manifest of today's or an older format is read, a newer one asks to
// update sshr (#97)
func TestManifestFormats(t *testing.T) {
	for v, ok := range map[int]bool{0: false, 1: true, 2: false} {
		err := checkFormat(v)
		if (err == nil) != ok {
			t.Errorf("format %d: %v", v, err)
		}
	}
	if err := checkFormat(2); err == nil || !strings.Contains(err.Error(), "update sshr") {
		t.Errorf("a newer format does not ask to update: %v", err)
	}
}

// the sync state keeps keys a newer sshr wrote, a state of a newer format
// stops the sync and asks to update (#97)
func TestSyncStateKeepsKeysItDoesNotKnow(t *testing.T) {
	w := newWorld(t)
	w.pair()
	path := w.a.statePath()
	b, err := os.ReadFile(path)
	must(t, err)
	var m map[string]any
	must(t, json.Unmarshal(b, &m))
	m["future"] = "kept"
	b, _ = json.Marshal(m)
	must(t, os.WriteFile(path, b, 0o600))
	w.a.st = nil
	must(t, w.a.Push())
	if raw := readFileKeys(t, path); string(raw["future"]) != `"kept"` {
		t.Fatalf("state.json lost the key: %v", raw)
	}
	m["version"] = 4
	b, _ = json.Marshal(m)
	must(t, os.WriteFile(path, b, 0o600))
	w.a.st = nil
	if err := w.a.Push(); err == nil || !strings.Contains(err.Error(), "update sshr") {
		t.Fatalf("a newer state was used: %v", err)
	}
}

func readFileKeys(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	b, err := os.ReadFile(path)
	must(t, err)
	var m map[string]json.RawMessage
	must(t, json.Unmarshal(b, &m))
	return m
}

// a host of a newer format is refused before its saved password is
// opened, the sync does not reach the keychain for a host it leaves out
// (#168)
func TestPayloadOfNewerHostOpensNoPassword(t *testing.T) {
	// never the real keychain or home, even when the order breaks again
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	dir := t.TempDir()
	s := &app.Store{Dir: dir}
	id := "0123456789abcdef0123456789abcdef"
	raw := `{"version":2,"id":"` + id + `","name":"w","host":"h","user":"u","password_mode":"saved","password_sealed":"v2:not-a-seal"}`
	must(t, os.WriteFile(filepath.Join(dir, id+".json"), []byte(raw), 0o600))
	h, err := s.Find(id)
	must(t, err)
	if _, err := payloadOf(*h); !errors.Is(err, app.ErrNewerFormat) {
		t.Fatalf("the password was opened first: %v", err)
	}
}
