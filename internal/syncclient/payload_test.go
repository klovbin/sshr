package syncclient

import (
	"reflect"
	"strings"
	"testing"
	"time"

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
		// a key file path and an agent socket of this machine travel as they
		// are, FromOtherDevice does not reset them yet, see #100
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
