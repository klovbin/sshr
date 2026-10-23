package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"sshr.dev/internal/app"
)

func TestJSONShapes(t *testing.T) {
	h := &app.Host{ID: "abc", Name: "web", Host: "10.0.0.1", User: "u", Port: 22, PasswordMode: app.PasswordSaved,
		Password: "s3cret", PasswordSealed: "v2:sealed", Tags: []string{"prod"}}
	b, _ := json.Marshal([]listJSON{{HostSummary: h.Summary(), Status: &healthJSON{State: "up", LatencyMS: 12}}})
	s := string(b)
	for _, want := range []string{`"name":"web"`, `"address":"10.0.0.1"`, `"tags":["prod"]`, `"status":{"state":"up","latency_ms":12}`} {
		if !strings.Contains(s, want) {
			t.Errorf("list JSON has no %s: %s", want, s)
		}
	}
	if strings.Contains(s, "s3cret") || strings.Contains(s, "sealed") {
		t.Fatalf("list JSON carries a secret: %s", s)
	}
	b, _ = json.Marshal(pingJSON{Name: "web", ID: "abc", healthJSON: toHealthJSON(app.Health{State: "down", Latency: 3 * time.Millisecond, Reason: "refused"})})
	if string(b) != `{"name":"web","id":"abc","state":"down","latency_ms":3,"reason":"refused"}` {
		t.Errorf("ping JSON = %s", b)
	}
}
