package ext

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// DefaultCatalog is the community catalog of extensions, extensions/
// catalog.json in the sshr repository, an author adds an entry with a pull
// request, the code stays in the author's repository, a setting points
// sshr at another catalog, a company can run its own
const DefaultCatalog = "https://raw.githubusercontent.com/klovbin/sshr/main/extensions/catalog.json"

// Entry is one extension of the catalog, the commit is the one the entry
// was added with, an install takes that commit and nothing newer
type Entry struct {
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	Commit      string   `json:"commit"`
	Description string   `json:"description"`
	Author      string   `json:"author"`
	Kinds       []string `json:"kinds"`
}

// catalogFile is the index.json of a catalog
type catalogFile struct {
	Version    int     `json:"version"`
	Extensions []Entry `json:"extensions"`
}

const (
	// catalogMax bounds the index, a few thousand entries fit
	catalogMax = 4 << 20
	// catalogTimeout bounds the download of the index
	catalogTimeout = 30 * time.Second
	// textMax bounds a description or author shown in the terminal
	textMax = 300
)

// CheckCatalogURL takes an https address, plain http only to a loopback IP
// for a catalog on this machine
func CheckCatalogURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("bad catalog address, it has to look like https://host/path/index.json")
	}
	if u.User != nil {
		return errors.New("the catalog address must not carry a user or password")
	}
	if u.Scheme == "https" {
		return nil
	}
	if ip := net.ParseIP(u.Hostname()); u.Scheme == "http" && ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("the catalog address has to be https://: %s", u.Redacted())
}

// FetchCatalog reads the catalog at addr, entries that do not pass the
// checks are left out and named in the warnings, a redirect is followed
// only to another https address
func FetchCatalog(addr string, client *http.Client) ([]Entry, []string, error) {
	if err := CheckCatalogURL(addr); err != nil {
		return nil, nil, err
	}
	c := http.Client{Timeout: catalogTimeout}
	if client != nil {
		c = *client
		if c.Timeout == 0 {
			c.Timeout = catalogTimeout
		}
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		// plain http on this machine is for a catalog set by hand, a
		// redirect must not reach a local service through it
		if req.URL.Scheme != "https" {
			return fmt.Errorf("the catalog redirects to %s, only https is followed", req.URL.Redacted())
		}
		return CheckCatalogURL(req.URL.String())
	}
	resp, err := c.Get(addr)
	if err != nil {
		return nil, nil, fmt.Errorf("the catalog %s is not reachable: %w", addr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("the catalog %s answered %d", addr, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, catalogMax+1))
	if err != nil {
		return nil, nil, fmt.Errorf("the catalog %s: %w", addr, err)
	}
	if len(b) > catalogMax {
		return nil, nil, fmt.Errorf("the catalog %s is larger than %d MiB", addr, catalogMax>>20)
	}
	return parseCatalog(b)
}

// parseCatalog checks every entry, a name taken twice keeps neither, the
// catalog must not decide by order which of two code bases a name means
func parseCatalog(b []byte) ([]Entry, []string, error) {
	var f catalogFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, nil, fmt.Errorf("the catalog is damaged: %v", err)
	}
	if f.Version != 1 {
		return nil, nil, fmt.Errorf("the catalog is of version %d, this sshr reads version 1, update sshr", f.Version)
	}
	var warnings []string
	count := map[string]int{}
	for _, e := range f.Extensions {
		count[e.Name]++
	}
	var out []Entry
	for _, e := range f.Extensions {
		if err := checkEntry(e); err != nil {
			warnings = append(warnings, fmt.Sprintf("catalog entry %s left out: %v", clean(e.Name, 64), err))
			continue
		}
		if count[e.Name] > 1 {
			warnings = append(warnings, fmt.Sprintf("catalog entry %s left out: the name is there %d times", e.Name, count[e.Name]))
			continue
		}
		e.Description, e.Author = clean(e.Description, textMax), clean(e.Author, textMax)
		out = append(out, e)
	}
	return out, warnings, nil
}

// catalogURLRe is the characters an entry address may hold, no space, no
// control or bidi character that git would echo into the terminal
var catalogURLRe = regexp.MustCompile(`^[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{1,300}$`)

// checkEntry checks the format of an entry, not what its code does
func checkEntry(e Entry) error {
	if err := CheckName(e.Name); err != nil {
		return err
	}
	if !strings.HasPrefix(e.URL, "https://") || !isGitURL(e.URL) || !catalogURLRe.MatchString(e.URL) {
		return fmt.Errorf("the address %q is not an https git address of plain URL characters", clean(e.URL, 200))
	}
	if !commitRe.MatchString(e.Commit) {
		return errors.New("no full commit hash")
	}
	for _, k := range e.Kinds {
		if k != KindCommand && k != KindImport {
			return fmt.Errorf("unknown kind %q", clean(k, 32))
		}
	}
	return nil
}

// CleanText is clean for text sshr prints that came from elsewhere, a
// recorded source of an extension
func CleanText(s string, max int) string { return clean(s, max) }

// clean drops control characters and cuts s at max runes, text from a
// catalog must not move the cursor or change the terminal
func clean(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) || r == ' ' || r == ' ' || unicode.In(r, unicode.Bidi_Control) {
			continue
		}
		if n++; n > max {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Search keeps the entries that hold every word in the name, description,
// author or kinds, no words keeps all
func Search(entries []Entry, words []string) []Entry {
	var out []Entry
	for _, e := range entries {
		hay := strings.ToLower(e.Name + " " + e.Description + " " + e.Author + " " + strings.Join(e.Kinds, " "))
		ok := true
		for _, w := range words {
			if !strings.Contains(hay, strings.ToLower(w)) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, e)
		}
	}
	return out
}

// Lookup is the entry called name
func Lookup(entries []Entry, name string) (Entry, bool) {
	for _, e := range entries {
		if e.Name == name {
			return e, true
		}
	}
	return Entry{}, false
}
