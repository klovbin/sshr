package main

import (
	"testing"
	"time"

	"sshr.dev/internal/app"
)

func TestPickHosts(t *testing.T) {
	s := &app.Store{Dir: t.TempDir()}
	add := func(name string, tags ...string) {
		t.Helper()
		if _, err := s.Add(app.Host{Name: name, Host: "10.0.0.1", User: "u", PasswordMode: app.PasswordAsk, Tags: tags}); err != nil {
			t.Fatal(err)
		}
		// List is newest first, the times keep the order fixed
		time.Sleep(2 * time.Millisecond)
	}
	add("a", "prod", "eu")
	add("b", "prod")
	add("c", "eu")
	add("d")
	names := func(hs []app.Host) string { return hostNames(hs) }
	if got := names(pickHosts(s, nil, []string{"prod", "eu"})); got != "a" {
		t.Errorf("all tags = %s", got)
	}
	if got := names(pickHosts(s, []string{"d", "a"}, []string{"prod"})); got != "d, b, a" {
		t.Errorf("names and a tag, in list order, once each = %s", got)
	}
	if got := names(pickHosts(s, []string{"c"}, nil)); got != "c" {
		t.Errorf("a name only = %s", got)
	}
}
