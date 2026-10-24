// Package davstore keeps a sync account in a WebDAV folder, Nextcloud,
// ownCloud or any server that refuses a PUT with If-None-Match: * when the
// name is taken, the write that creates the next manifest only when nobody
// did
package davstore

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"sshr.dev/internal/syncclient"
)

// Config says where the account lives, the password is kept apart from it
// in the keychain
type Config struct {
	// URL is the folder of the account, for Nextcloud
	// https://host/remote.php/dav/files/<user>/sshr
	URL  string `json:"url"`
	User string `json:"user"`
}

// Store is a syncclient.ObjectStore in a WebDAV folder
type Store struct {
	base   *url.URL
	user   string
	pass   string
	client *http.Client
}

// requestTimeout bounds one request, a sync runs many small ones
const requestTimeout = time.Minute

// maxListing bounds the answer of one PROPFIND, a folder of an account
// holds at most a few thousand names
const maxListing = 16 << 20

// New opens the folder of cfg with the password secret
func New(cfg Config, secret string, client *http.Client) (*Store, error) {
	if cfg.URL == "" || cfg.User == "" || secret == "" {
		return nil, errors.New("a WebDAV store needs an address, a user and a password")
	}
	if err := syncclient.CheckStoreURL("WebDAV address", cfg.URL); err != nil {
		return nil, err
	}
	base, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, err
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/"
	base.RawPath = ""
	if client == nil {
		client = &http.Client{}
	}
	return &Store{base: base, user: cfg.User, pass: secret, client: client}, nil
}

// at is the address of name under the folder of the account
func (s *Store) at(name string) string {
	u := *s.base
	u.Path += name
	return u.String()
}

// do sends one request, the password goes in the header and never in an
// error
func (s *Store) do(method, name string, body []byte, hdr map[string]string) (*http.Response, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.at(name), r)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	req.SetBasicAuth(s.user, s.pass)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("WebDAV %s %s: %w", method, name, err)
	}
	return resp, cancel, nil
}

// statusError is an answer that is not one of the expected ones
func statusError(method, name string, code int) error {
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		return fmt.Errorf("WebDAV %s %s: the server refused the user or password (%d)", method, name, code)
	}
	return fmt.Errorf("WebDAV %s %s: the server answered %d", method, name, code)
}

// Get reads an object of at most max bytes
func (s *Store) Get(name string, max int) ([]byte, error) {
	resp, cancel, err := s.do("GET", name, nil, nil)
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, syncclient.ErrNotFound
	default:
		return nil, statusError("GET", name, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(max)+1))
	if err != nil {
		return nil, fmt.Errorf("WebDAV GET %s: %w", name, err)
	}
	if len(b) > max {
		return nil, syncclient.ErrTooLarge
	}
	return b, nil
}

// put writes data, the folders above name are made when the server says
// they are missing, it answers the status of the write
func (s *Store) put(name string, data []byte, hdr map[string]string) (int, error) {
	for try := 0; ; try++ {
		resp, cancel, err := s.do("PUT", name, data, hdr)
		if err != nil {
			return 0, err
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		cancel()
		// RFC 4918 9.7.1 answers 409 for a missing folder, some servers 404
		missing := resp.StatusCode == http.StatusConflict || resp.StatusCode == http.StatusNotFound
		if !missing || try > 0 {
			return resp.StatusCode, nil
		}
		if err := s.mkcols(name); err != nil {
			return 0, err
		}
	}
}

// mkcols makes the folder of the account and every folder above name,
// one that is there answers 405
func (s *Store) mkcols(name string) error {
	dirs := []string{""}
	parts := strings.Split(name, "/")
	for i := 1; i < len(parts); i++ {
		dirs = append(dirs, strings.Join(parts[:i], "/")+"/")
	}
	for _, d := range dirs {
		resp, cancel, err := s.do("MKCOL", d, nil, nil)
		if err != nil {
			return err
		}
		resp.Body.Close()
		cancel()
		switch resp.StatusCode {
		case http.StatusCreated, http.StatusMethodNotAllowed, http.StatusOK:
		default:
			return statusError("MKCOL", d, resp.StatusCode)
		}
	}
	return nil
}

func written(code int) bool {
	return code == http.StatusOK || code == http.StatusCreated || code == http.StatusNoContent
}

// Put writes an object over any that is there
func (s *Store) Put(name string, data []byte) error {
	code, err := s.put(name, data, nil)
	if err != nil {
		return err
	}
	if !written(code) {
		return statusError("PUT", name, code)
	}
	return nil
}

// Create writes an object only when the name is free, the server answers
// 412 to If-None-Match: * when it is taken
func (s *Store) Create(name string, data []byte) error {
	code, err := s.put(name, data, map[string]string{"If-None-Match": "*"})
	if err != nil {
		return err
	}
	switch {
	case written(code):
		return nil
	case code == http.StatusPreconditionFailed:
		return syncclient.ErrExists
	default:
		return statusError("PUT", name, code)
	}
}

// Delete removes an object, a missing one is no error
func (s *Store) Delete(name string) error {
	resp, cancel, err := s.do("DELETE", name, nil, nil)
	if err != nil {
		return err
	}
	defer cancel()
	resp.Body.Close()
	if written(resp.StatusCode) || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return statusError("DELETE", name, resp.StatusCode)
}

// multistatus is the part of a PROPFIND answer List reads
type multistatus struct {
	Responses []struct {
		Href       string    `xml:"href"`
		Collection *struct{} `xml:"propstat>prop>resourcetype>collection"`
	} `xml:"response"`
}

const propfindBody = `<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/></d:prop></d:propfind>`

// List names the objects in the folder prefix, without the folder of the
// account, every prefix sync lists is one folder deep, so Depth 1 is
// enough and servers that refuse Depth infinity work
func (s *Store) List(prefix string) ([]string, error) {
	dir := strings.TrimRight(prefix, "/") + "/"
	resp, cancel, err := s.do("PROPFIND", dir, []byte(propfindBody), map[string]string{
		"Depth": "1", "Content-Type": "application/xml; charset=utf-8",
	})
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusMultiStatus:
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, statusError("PROPFIND", dir, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxListing+1))
	if err != nil {
		return nil, fmt.Errorf("WebDAV PROPFIND %s: %w", dir, err)
	}
	if len(b) > maxListing {
		return nil, fmt.Errorf("WebDAV PROPFIND %s: the listing is larger than a sync account holds", dir)
	}
	var ms multistatus
	if err := xml.Unmarshal(b, &ms); err != nil {
		return nil, fmt.Errorf("WebDAV PROPFIND %s: %w", dir, err)
	}
	want := path.Clean(s.base.Path + dir)
	var out []string
	for _, r := range ms.Responses {
		if r.Collection != nil {
			continue
		}
		u, err := url.Parse(strings.TrimSpace(r.Href))
		if err != nil {
			continue
		}
		p := path.Clean(u.Path)
		// only the direct children of the folder asked for
		if path.Dir(p) != want {
			continue
		}
		out = append(out, prefix+path.Base(p))
	}
	return out, nil
}
