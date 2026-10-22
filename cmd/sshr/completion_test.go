package main

import (
	"slices"
	"testing"

	"sshr.dev/internal/app"
)

func TestComplete(t *testing.T) {
	s := &app.Store{Dir: t.TempDir()}
	s.Add(app.Host{Name: "web", Host: "10.0.0.1", User: "u", PasswordMode: app.PasswordAsk, Tags: []string{"prod"},
		Forwards: []app.Forward{{Name: "db", Kind: "L", Spec: "5432:localhost:5432"}}})
	s.Add(app.Host{Name: "worker", Host: "10.0.0.2", User: "u", PasswordMode: app.PasswordAsk, Tags: []string{"eu"}})
	cases := []struct {
		words []string
		cur   string
		want  []string
	}{
		{nil, "tu", []string{"tunnel"}},
		{nil, "ex", []string{"export", "ext"}},
		{[]string{"connect"}, "w", []string{"web", "worker"}},
		{[]string{"connect", "web"}, "", nil},
		{[]string{"tunnel", "web"}, "", []string{"db"}},
		{[]string{"connect", "web", "-F"}, "", []string{"db", "all"}},
		{[]string{"run", "-t"}, "", []string{"eu", "prod"}},
		{[]string{"tag", "web"}, "-", []string{"-prod"}},
		{[]string{"export"}, "--", []string{"--install", "--uninstall"}},
		{[]string{"sync"}, "re", []string{"remove-device"}},
		{[]string{"help"}, "imp", []string{"import"}},
		{[]string{"send", "web"}, "", nil},
	}
	for _, c := range cases {
		got := complete(s, c.words, c.cur)
		if !slices.Equal(got, c.want) {
			t.Errorf("complete(%q, %q) = %q, want %q", c.words, c.cur, got, c.want)
		}
	}
}
