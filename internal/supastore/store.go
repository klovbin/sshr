// Package supastore keeps a sync account in a Supabase project, in a table
// the Data API does not expose, reached only through functions that check
// the sshr key of the account first, see setup.sql
package supastore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
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

	"sshr.dev/internal/syncclient"
)

//go:embed setup.sql
var setupSQL string

// Config says which project holds the account, the publishable key is
// public by design, the sshr key is kept apart in the keychain
type Config struct {
	URL string `json:"url"`
	Key string `json:"key"`
}

// Store is a syncclient.ObjectStore in a Supabase project
type Store struct {
	base   string
	apikey string
	key    string
	client *http.Client
}

const (
	// requestTimeout bounds one call, an 8 MiB manifest is about 11 MB of
	// JSON
	requestTimeout = 2 * time.Minute
	// listPage is what one sshr_list returns, the max_rows of Supabase
	listPage = 1000
	// errorMax bounds an error answer read
	errorMax = 64 << 10
	// smallAnswer bounds the answer of a write or delete, it has no body
	smallAnswer = 64 << 10
	// listAnswer bounds a page of names, a name is at most 76 bytes
	listAnswer = 1 << 20
)

var keyRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// nameRe is the check of names in setup.sql, a listed name of another
// shape is a project that does not run that SQL
var nameRe = regexp.MustCompile(`^(account|devices/[0-9a-f]{32}|envelopes/[0-9a-f]{32}/[0-9]{10}|blobs/[0-9a-f]{64}|manifests/[0-9]{20}|probe/[0-9a-f]{16})$`)

// listMax bounds the names one List takes, more than an account holds
const listMax = 20000

// ErrKeyRefused means the project does not know the sshr key of this
// device, another device changed it
var ErrKeyRefused = errors.New("the Supabase project refused the sshr key of this account, run sshr sync store-key with the key the other devices use")

// NewKey makes the sshr key of a new account
func NewKey() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// SetupSQL is the SQL the user runs once in the project, with the hash of
// key in it, never the key itself, replace drops the keys there were, after
// a removed device the old key must stop working
func SetupSQL(key string, replace bool) string {
	sum := sha256.Sum256([]byte(key))
	sql := strings.Replace(setupSQL, "{{KEY_HASH}}", hex.EncodeToString(sum[:]), 1)
	if replace {
		sql = strings.Replace(sql, "insert into sshr.keys", "delete from sshr.keys;\ninsert into sshr.keys", 1)
	}
	return sql
}

// CheckKey takes a publishable key, a secret or service_role key reaches the
// whole project past every policy and must not sit on a device
func CheckKey(k string) error {
	switch {
	case strings.HasPrefix(k, "sb_secret_"):
		return errors.New("this is a secret key of the project, it opens everything, give the publishable key (sb_publishable_...)")
	case strings.HasPrefix(k, "sb_publishable_"):
		return nil
	}
	parts := strings.Split(k, ".")
	if len(parts) != 3 {
		return errors.New("this is not a publishable key of Supabase, it starts with sb_publishable_")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("this is not a publishable key of Supabase, it starts with sb_publishable_")
	}
	var claims struct {
		Role string `json:"role"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Role != "anon" {
		return fmt.Errorf("this key has the role %q, give the publishable or anon key, never service_role", claims.Role)
	}
	return nil
}

// New opens the project of cfg with the sshr key key
func New(cfg Config, key string, client *http.Client) (*Store, error) {
	if err := syncclient.CheckStoreURL("Supabase address", cfg.URL); err != nil {
		return nil, err
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, err
	}
	if strings.Trim(u.Path, "/") != "" {
		return nil, errors.New("the Supabase address is the project address alone, https://<ref>.supabase.co")
	}
	if err := CheckKey(cfg.Key); err != nil {
		return nil, err
	}
	if !keyRe.MatchString(key) {
		return nil, errors.New("the sshr key of a Supabase account is 64 hex characters")
	}
	// a redirect is never followed, the key header must not go elsewhere
	c := http.Client{}
	if client != nil {
		c = *client
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Store{base: strings.TrimRight(cfg.URL, "/") + "/rest/v1/rpc/", apikey: cfg.Key, key: key, client: &c}, nil
}

// rpc calls one function with a POST, every call goes to the primary
// database, a read replica never answers, an answer longer than limit is
// ErrTooLarge and is not read further
func (s *Store) rpc(fn string, args, out any, limit int64) error {
	body, err := json.Marshal(args)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", s.base+fn, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("apikey", s.apikey)
	if strings.Count(s.apikey, ".") == 2 {
		req.Header.Set("Authorization", "Bearer "+s.apikey)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-sshr-key", s.key)
	resp, err := s.client.Do(req)
	if err != nil {
		var dns *net.DNSError
		if errors.As(err, &dns) && dns.IsNotFound {
			return fmt.Errorf("the Supabase project %s does not resolve, it is paused or deleted, or there is no network", strings.TrimSuffix(s.base, "/rest/v1/rpc/"))
		}
		return fmt.Errorf("Supabase %s: %w", fn, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return fmt.Errorf("Supabase %s: %w", fn, err)
		}
		if int64(len(b)) > limit {
			return syncclient.ErrTooLarge
		}
		if out == nil {
			return nil
		}
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("Supabase %s: %v", fn, err)
		}
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, errorMax))
	var e struct {
		Code string `json:"code"`
	}
	json.Unmarshal(b, &e)
	return answerError(fn, resp.StatusCode, e.Code)
}

// answerError is the error an answer of the project means
func answerError(fn string, status int, code string) error {
	switch {
	case code == "PT404":
		return syncclient.ErrNotFound
	case code == "PT413":
		return syncclient.ErrTooLarge
	case code == "PT409":
		return syncclient.ErrExists
	case code == "PT403":
		return ErrKeyRefused
	case code == "PGRST202" || code == "PGRST205":
		return errors.New("the sshr functions are not in the Supabase project, run the SQL that sshr sync supabase-sql prints in its SQL editor")
	case code == "25006" || status == http.StatusMethodNotAllowed:
		return errors.New("the Supabase database is full and read-only, free space in the project dashboard, deleting through sshr fails too while it is")
	case status == 540:
		return errors.New("the Supabase project is paused, a free project sleeps after a week without requests, resume it in the dashboard")
	case status == http.StatusPaymentRequired:
		return fmt.Errorf("Supabase restricted the project for its quota or billing (%s)", code)
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return fmt.Errorf("Supabase refused the publishable key (%d %s)", status, code)
	case status >= 300 && status < 400:
		return fmt.Errorf("Supabase %s: the address redirects (%d), give the project address https://<ref>.supabase.co", fn, status)
	case status == http.StatusRequestEntityTooLarge:
		return syncclient.ErrTooLarge
	}
	return fmt.Errorf("Supabase %s answered %d %s", fn, status, code)
}

// Get reads an object of at most max bytes, the size is checked in the
// database, a bigger object is not sent
func (s *Store) Get(name string, max int) ([]byte, error) {
	var b64 string
	// base64 is 4/3 of the bytes, Postgres adds a line break every 76
	if err := s.rpc("sshr_get", map[string]any{"p_name": name, "p_max": max}, &b64, int64(max)*3/2+4096); err != nil {
		return nil, err
	}
	// encode in Postgres breaks lines, the decoder skips them
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("Supabase get %s: %v", name, err)
	}
	if len(b) > max {
		return nil, syncclient.ErrTooLarge
	}
	return b, nil
}

// Put writes an object over any that is there
func (s *Store) Put(name string, data []byte) error {
	return s.rpc("sshr_put", map[string]any{"p_name": name, "p_data": base64.StdEncoding.EncodeToString(data)}, nil, smallAnswer)
}

// Create writes an object only when the name is free, the primary key of
// the table decides between two at once, the same bytes again succeed
func (s *Store) Create(name string, data []byte) error {
	return s.rpc("sshr_create", map[string]any{"p_name": name, "p_data": base64.StdEncoding.EncodeToString(data)}, nil, smallAnswer)
}

// Delete removes an object, a missing one is no error
func (s *Store) Delete(name string) error {
	return s.rpc("sshr_delete", map[string]any{"p_name": name}, nil, smallAnswer)
}

// List names the objects under prefix, page by page
func (s *Store) List(prefix string) ([]string, error) {
	var out []string
	after := ""
	for {
		var page []struct {
			Name string `json:"name"`
		}
		if err := s.rpc("sshr_list", map[string]any{"p_prefix": prefix, "p_after": after}, &page, listAnswer); err != nil {
			return nil, err
		}
		for _, p := range page {
			if !strings.HasPrefix(p.Name, prefix) || p.Name <= after || !nameRe.MatchString(p.Name) {
				return nil, fmt.Errorf("Supabase list %s: the project answered names out of order or of another shape", prefix)
			}
			out = append(out, p.Name)
			after = p.Name
		}
		if len(out) > listMax {
			return nil, fmt.Errorf("Supabase list %s: more than %d names, more than a sync account holds", prefix, listMax)
		}
		if len(page) < listPage {
			return out, nil
		}
	}
}
