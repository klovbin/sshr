package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// addFutureField writes a field this build does not know into the host
// file, the way a newer sshr would
func addFutureField(t *testing.T, s *Store, id string) {
	t.Helper()
	path := filepath.Join(s.Dir, id+".json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m["future_field"] = map[string]any{"kept": true}
	b, _ = json.Marshal(m)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func hasFutureField(t *testing.T, s *Store, id string) bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.Dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return string(m["future_field"]) == `{"kept":true}`
}

// a field a newer sshr wrote survives every save of this one: an edit
// through a form that never saw the field, a copy of the host from the
// CLI, a gateway change and a connect (#97)
func TestHostKeepsFieldsItDoesNotKnow(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Name: "web", Host: "10.0.0.5", User: "u", PasswordMode: PasswordAsk})
	if err != nil {
		t.Fatal(err)
	}
	addFutureField(t, s, h.ID)

	form := Host{Name: "web", Host: "10.0.0.6", User: "u", PasswordMode: PasswordAsk}
	if _, err := s.Update(h.ID, form); err != nil {
		t.Fatal(err)
	}
	if !hasFutureField(t, s, h.ID) {
		t.Fatal("an edit from a form lost the field")
	}
	cur, _ := s.Find(h.ID)
	cur.Tags = []string{"prod"}
	if _, err := s.Update(h.ID, *cur); err != nil {
		t.Fatal(err)
	}
	if !hasFutureField(t, s, h.ID) {
		t.Fatal("an edit of a copy lost the field")
	}
	if _, err := s.SetGateway(h.ID, "gw"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkConnected(h.ID); err != nil {
		t.Fatal(err)
	}
	if !hasFutureField(t, s, h.ID) {
		t.Fatal("a gateway change or a connect lost the field")
	}
}

// a host with no unknown keys is written byte for byte as before, a
// cleared field stays gone and a case variant of a known key is no extra
func TestHostRecordBytes(t *testing.T) {
	h := Host{ID: "0123456789abcdef0123456789abcdef", Name: "w", Host: "h", User: "u"}
	plain, _ := json.MarshalIndent(&h, "", "  ")
	got, err := encodeHost(&h)
	if err != nil || string(got) != string(plain) {
		t.Fatalf("a plain host changed:\n%s\n%s", got, plain)
	}
	in := `{"id":"0123456789abcdef0123456789abcdef","name":"w","host":"h","user":"u","Key_Sealed":"v1:old","future":[1,2]}`
	h, err = decodeHost([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.extra) != 1 || string(h.extra["future"]) != "[1,2]" || h.KeySealed != "v1:old" {
		t.Fatalf("extra %v, key sealed %q", h.extra, h.KeySealed)
	}
	h.KeySealed = ""
	out, err := encodeHost(&h)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]json.RawMessage
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, ok := back["key_sealed"]; ok || string(back["future"]) != "[1,2]" {
		t.Fatalf("written %s", out)
	}
	for k := range back {
		if strings.EqualFold(k, "key_sealed") {
			t.Fatalf("a cleared field came back as %s", k)
		}
	}
}

// a host file of a newer format is listed and can be connected to, it is
// never written by this build and its bytes stay as they are
func TestNewerHostFileIsReadOnly(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Name: "web", Host: "10.0.0.5", User: "u", PasswordMode: PasswordAsk})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.Dir, h.ID+".json")
	b, _ := os.ReadFile(path)
	var m map[string]any
	json.Unmarshal(b, &m)
	m["version"] = 99
	b, _ = json.Marshal(m)
	os.WriteFile(path, b, 0o600)
	got, err := s.Find(h.ID)
	if err != nil || got.Host != "10.0.0.5" {
		t.Fatalf("a newer file does not read: %v", err)
	}
	if _, err := s.Update(h.ID, Host{Name: "web", Host: "10.0.0.6", User: "u", PasswordMode: PasswordAsk}); !errors.Is(err, ErrNewerFormat) {
		t.Errorf("update: %v", err)
	}
	if _, err := s.SetGateway(h.ID, "gw"); !errors.Is(err, ErrNewerFormat) {
		t.Errorf("gateway: %v", err)
	}
	s.MarkConnected(h.ID)
	if after, _ := os.ReadFile(path); string(after) != string(b) {
		t.Fatalf("the newer file was written:\n%s", after)
	}
	if err := s.Delete(h.ID); err != nil {
		t.Errorf("a newer host cannot be removed: %v", err)
	}
}

// a host file of a newer format whose known field changed type is read
// with what decodes, read only, not reported as broken (#162)
func TestNewerHostWithChangedFieldReads(t *testing.T) {
	h, err := decodeHost([]byte(`{"version":2,"id":"0123456789abcdef0123456789abcdef","name":"w","host":"h","user":"u","port":"22"}`))
	if err != nil || h.Host != "h" || h.format != 2 {
		t.Fatalf("%+v %v", h, err)
	}
	if _, err := encodeHost(&h); !errors.Is(err, ErrNewerFormat) {
		t.Errorf("written: %v", err)
	}
	if _, err := decodeHost([]byte(`{"id":"x","port":"22"}`)); err == nil {
		t.Error("a damaged file of today's format read")
	}
}
