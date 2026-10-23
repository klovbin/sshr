package main

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
	"time"

	"sshr.dev/internal/app"
)

func TestShow(t *testing.T) {
	s := &app.Store{Dir: t.TempDir()}
	bastion, err := s.Add(app.Host{Name: "bastion", Host: "10.0.0.9", User: "j", PasswordMode: app.PasswordAsk})
	if err != nil {
		t.Fatal(err)
	}
	h, err := s.Add(app.Host{Name: "web", Host: "10.0.0.1", User: "deploy", Port: 2222, PasswordMode: app.PasswordAsk,
		Jump: bastion.Name, Session: "tmux", Tags: []string{"prod"}})
	if err != nil {
		t.Fatal(err)
	}
	argv, err := connectCommand(s, h)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	writeShow(&b, h, argv, time.Now())
	out := b.String()
	for _, want := range []string{"deploy@10.0.0.1:2222", "jump hosts      bastion", "session         tmux", "tags            prod", "last connect    -", "sshr connect runs:", "-t -- deploy@10.0.0.1"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	// the printed line runs as the same argv in a shell
	if _, err := exec.LookPath("sh"); err == nil {
		line := shellLine([]string{"printf", "%s\n", "a b", "it's", "$HOME", "x"})
		got, err := exec.Command("sh", "-c", line).Output()
		if err != nil || string(got) != "a b\nit's\n$HOME\nx\n" {
			t.Fatalf("shellLine %q ran as %q, %v", line, got, err)
		}
	}
}

func TestShowNeverPrintsPasswords(t *testing.T) {
	h := &app.Host{Name: "w", Host: "10.0.0.1", User: "u", Port: 22, PasswordMode: app.PasswordSaved, Password: "s3cret"}
	var b bytes.Buffer
	writeShow(&b, h, []string{"ssh", "--", h.Dest()}, time.Now())
	if strings.Contains(b.String(), "s3cret") {
		t.Fatal("the password was printed")
	}
}
