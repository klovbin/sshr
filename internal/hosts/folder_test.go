package hosts

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestCleanFolder(t *testing.T) {
	got, err := CleanFolder(" Work/Prod ")
	if err != nil || got != "work/prod" {
		t.Fatalf("got %q %v", got, err)
	}
	if _, err := CleanFolder("bad name"); err == nil {
		t.Fatal("space should fail")
	}
	if _, err := CleanFolder("../x"); err == nil {
		t.Fatal("relative should fail")
	}
	got, err = CleanFolder("")
	if err != nil || got != "" {
		t.Fatalf("empty: %q %v", got, err)
	}
}

func TestFoldersRegistry(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	if _, err := s.AddFolder("work"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddFolder("work/prod"); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListFolders()
	if err != nil || !slices.Equal(list, []string{"work", "work/prod"}) {
		t.Fatalf("list=%v err=%v", list, err)
	}
	h, err := s.Add(Host{Name: "web", Host: "10.0.0.1", User: "u", PasswordMode: PasswordAsk, Folder: "work/prod"})
	if err != nil {
		t.Fatal(err)
	}
	if h.Folder != "work/prod" {
		t.Fatalf("folder=%q", h.Folder)
	}
	if _, err := s.SetFolder(h.ID, "home"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Find(h.ID)
	if err != nil || got.Folder != "home" {
		t.Fatalf("moved: %+v %v", got, err)
	}
	list, err = s.ListFolders()
	if err != nil || !slices.Contains(list, "home") || !slices.Contains(list, "work") {
		t.Fatalf("after move list=%v", list)
	}
	if err := s.RemoveFolder("home", false); err == nil {
		t.Fatal("remove with host should fail")
	}
	if err := s.RemoveFolder("home", true); err != nil {
		t.Fatal(err)
	}
	got, err = s.Find(h.ID)
	if err != nil || got.Folder != "" {
		t.Fatalf("force clear: %+v %v", got, err)
	}
	// folders.json skipped by List
	if _, err := s.AddFolder("alone"); err != nil {
		t.Fatal(err)
	}
	hosts, broken, err := s.ListAll()
	if err != nil || len(broken) != 0 {
		t.Fatalf("hosts=%d broken=%v err=%v", len(hosts), broken, err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, foldersFile)); err != nil {
		t.Fatal(err)
	}
}
