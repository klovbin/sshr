package ext

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const goodCommit = "0123456789abcdef0123456789abcdef01234567"

// the catalog keeps only entries of the right shape, a name taken twice
// keeps neither, text that could drive the terminal is cleaned (#170)
func TestParseCatalog(t *testing.T) {
	b := []byte(`{"version":1,"extensions":[
		{"name":"hello","url":"https://example.com/hello.git","commit":"` + goodCommit + `","description":"says hi\u001b[2J‮","author":"Ann","kinds":["command"]},
		{"name":"twice","url":"https://example.com/a.git","commit":"` + goodCommit + `","kinds":["import"]},
		{"name":"twice","url":"https://example.com/b.git","commit":"` + goodCommit + `","kinds":["import"]},
		{"name":"plain","url":"http://example.com/p.git","commit":"` + goodCommit + `"},
		{"name":"short","url":"https://example.com/s.git","commit":"abc"},
		{"name":"../x","url":"https://example.com/x.git","commit":"` + goodCommit + `"},
		{"name":"odd","url":"https://example.com/o.git","commit":"` + goodCommit + `","kinds":["daemon"]},
		{"name":"scp","url":"git@example.com:a/b.git","commit":"` + goodCommit + `"}
	]}`)
	entries, warnings, err := parseCatalog(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "hello" {
		t.Fatalf("entries %+v", entries)
	}
	if d := entries[0].Description; d != "says hi[2J" {
		t.Errorf("description %q", d)
	}
	if len(warnings) != 7 {
		t.Errorf("warnings %q", warnings)
	}
	if _, _, err := parseCatalog([]byte(`{"version":2,"extensions":[]}`)); err == nil || !strings.Contains(err.Error(), "version 2") {
		t.Errorf("a newer catalog: %v", err)
	}
	if got := clean(strings.Repeat("a", 400), textMax); len([]rune(got)) != textMax+1 {
		t.Errorf("a long text is %d runes", len([]rune(got)))
	}
}

func TestSearchAndLookup(t *testing.T) {
	entries := []Entry{
		{Name: "remmina", Description: "imports Remmina profiles", Kinds: []string{"import"}},
		{Name: "hello", Description: "says hi", Author: "Ann", Kinds: []string{"command"}},
	}
	if got := Search(entries, []string{"IMPORT"}); len(got) != 1 || got[0].Name != "remmina" {
		t.Errorf("search import %+v", got)
	}
	if got := Search(entries, []string{"ann", "hi"}); len(got) != 1 || got[0].Name != "hello" {
		t.Errorf("search ann hi %+v", got)
	}
	if got := Search(entries, nil); len(got) != 2 {
		t.Errorf("search all %+v", got)
	}
	if _, ok := Lookup(entries, "hello"); !ok {
		t.Error("lookup hello")
	}
	if _, ok := Lookup(entries, "nope"); ok {
		t.Error("lookup nope")
	}
}

// the catalog comes over https, a redirect to plain http is refused, a
// catalog larger than the limit is refused (#170)
func TestFetchCatalog(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"version":1,"extensions":[]}`))
	}))
	defer plain.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.json":
			w.Write([]byte(`{"version":1,"extensions":[{"name":"hello","url":"https://example.com/h.git","commit":"` + goodCommit + `","kinds":["command"]}]}`))
		case "/away":
			http.Redirect(w, r, "http://example.com/index.json", http.StatusFound)
		case "/big":
			w.Write([]byte(strings.Repeat(" ", catalogMax+10)))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	entries, _, err := FetchCatalog(srv.URL+"/index.json", srv.Client())
	if err != nil || len(entries) != 1 {
		t.Fatalf("fetch %+v %v", entries, err)
	}
	if _, _, err := FetchCatalog(srv.URL+"/away", srv.Client()); err == nil {
		t.Error("followed a redirect to plain http")
	}
	if _, _, err := FetchCatalog(srv.URL+"/big", srv.Client()); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("a big catalog: %v", err)
	}
	if _, _, err := FetchCatalog(srv.URL+"/missing", srv.Client()); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("a missing catalog: %v", err)
	}
	if _, _, err := FetchCatalog("http://example.com/index.json", nil); err == nil {
		t.Error("fetched a plain http catalog on another host")
	}
	if _, _, err := FetchCatalog(plain.URL, nil); err != nil {
		t.Errorf("a catalog on this machine over http: %v", err)
	}
}
