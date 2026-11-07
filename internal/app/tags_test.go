package app

import (
	"strings"
	"testing"
)

func TestCleanTags(t *testing.T) {
	got, err := CleanTags(SplitTags("Prod, #db  prod\tclient-x"))
	if err != nil || strings.Join(got, ",") != "client-x,db,prod" {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"has space", "-lead", "a;b", strings.Repeat("x", 33)} {
		if _, err := CleanTags([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestMatches(t *testing.T) {
	h := Host{Name: "Web Prod", Host: "10.0.0.5", User: "deploy", Folder: "work/prod", Tags: []string{"prod", "web"}}
	for q, want := range map[string]bool{
		"":              true,
		"web":           true,
		"PROD 10.0":     true,
		"tag:prod":      true,
		"#web deploy":   true,
		"tag:pro":       false,
		"#db":           false,
		"prod staging":  false,
		"folder:work":   true,
		"folder:work/prod": true,
		"folder:home":   false,
		"folder:":       false,
	} {
		if got := h.Matches(q); got != want {
			t.Errorf("%q: %v", q, got)
		}
	}
}

func TestTagsSaved(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	h, err := s.Add(Host{Host: "h", User: "u", PasswordMode: PasswordAsk, Tags: []string{"DB", "prod"}})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.Find(h.ID)
	if strings.Join(got.Tags, ",") != "db,prod" {
		t.Fatalf("tags = %v", got.Tags)
	}
	if _, err := s.Add(Host{Host: "h2", User: "u", Tags: []string{"bad tag"}}); err == nil {
		t.Fatal("bad tag saved")
	}
}
