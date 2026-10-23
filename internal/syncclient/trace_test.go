package syncclient

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"sshr.dev/internal/hosts"
)

var updateTrace = flag.Bool("update-trace", false, "rewrite testdata/http-trace.golden")

// traceRT records every request of one device with the answer of the
// server, the trace shows what the client asks the server and how it
// reads the answer
type traceRT struct {
	mu    *sync.Mutex
	lines *[]string
	who   string
	// lose answers the next manifest put with 412, a race lost to
	// another device
	lose *bool
}

func (t traceRT) RoundTrip(r *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error
	if *t.lose && r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/manifest") {
		*t.lose = false
		resp = answer(http.StatusPreconditionFailed)
	} else if resp, err = http.DefaultTransport.RoundTrip(r); err != nil {
		return nil, err
	}
	line := fmt.Sprintf("%s %s %s", t.who, r.Method, r.URL.RequestURI())
	if m := r.Header.Get("If-Match"); m != "" {
		line += " if-match=" + m
	}
	if r.Header.Get("Authorization") != "" {
		line += " auth"
	}
	line += fmt.Sprintf(" -> %d", resp.StatusCode)
	t.mu.Lock()
	*t.lines = append(*t.lines, line)
	t.mu.Unlock()
	return resp, nil
}

var hashRe = regexp.MustCompile(`[0-9a-f]{64}`)

// normalize puts names in place of the random IDs and collapses repeated
// lines, blobs go up and down in map order
func normalize(lines []string, names map[string]string) string {
	var out []string
	last, count := "", 0
	flush := func() {
		if count == 1 {
			out = append(out, last)
		} else if count > 1 {
			out = append(out, fmt.Sprintf("%s x%d", last, count))
		}
	}
	for _, l := range lines {
		for id, name := range names {
			l = strings.ReplaceAll(l, id, name)
		}
		l = hashRe.ReplaceAllString(l, "<hash>")
		if l == last {
			count++
			continue
		}
		flush()
		last, count = l, 1
	}
	flush()
	return strings.Join(out, "\n") + "\n"
}

// the requests the client makes and the answers it accepts stay the same
// while the transport moves behind an interface (#128)
func TestHTTPTrace(t *testing.T) {
	w := newWorld(t)
	var mu sync.Mutex
	var lines []string
	lose := false
	w.a.HTTP = &http.Client{Transport: traceRT{&mu, &lines, "a", &lose}}
	w.b.HTTP = &http.Client{Transport: traceRT{&mu, &lines, "b", &lose}}
	web, _ := w.pair()

	h, err := w.a.Store.Find(web.ID)
	must(t, err)
	h.Port = 2201
	_, err = w.a.Store.Update(web.ID, *h)
	must(t, err)
	must(t, w.a.Push())

	must(t, w.b.Pull())
	_, err = w.b.Store.Add(hosts.Host{Name: "cache", Host: "10.0.0.3", User: "u"})
	must(t, err)
	lose = true
	must(t, w.b.Push())

	c := w.client("c-")
	c.HTTP = &http.Client{Transport: traceRT{&mu, &lines, "c", &lose}}
	w.join(c)
	_, err = w.a.RemoveDevice(c.st.DeviceID[:8])
	must(t, err)
	must(t, w.b.Pull())

	names := map[string]string{
		w.a.st.Account:  "<account>",
		w.a.st.DeviceID: "<dev-a>",
		w.b.st.DeviceID: "<dev-b>",
		c.st.DeviceID:   "<dev-c>",
	}
	got := normalize(lines, names)
	path := filepath.Join("testdata", "http-trace.golden")
	if *updateTrace {
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v, run go test -run TestHTTPTrace -update-trace once", err)
	}
	if got != string(want) {
		t.Errorf("the requests changed, got:\n%s\nwant:\n%s", got, want)
	}
}
