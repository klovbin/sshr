package app

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var (
	ErrHostEmpty    = errors.New("host_empty")
	ErrUserRequired = errors.New("user_required")
)

type Host struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	User      string    `json:"user"`
	CreatedAt time.Time `json:"created_at"`
}

type Store struct {
	Dir string
}

func DefaultStore() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, ".sshr", "vault", "hosts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{Dir: dir}, nil
}

func (s *Store) Add(name, host, user string, port int) (*Host, error) {
	name = strings.TrimSpace(name)
	host = strings.TrimSpace(host)
	user = strings.TrimSpace(user)
	if host == "" {
		return nil, ErrHostEmpty
	}
	if user == "" {
		return nil, ErrUserRequired
	}
	if name == "" {
		name = host
	}
	if port <= 0 {
		port = 22
	}

	id, err := newID()
	if err != nil {
		return nil, err
	}
	h := &Host{
		ID:        id,
		Name:      name,
		Host:      host,
		Port:      port,
		User:      user,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.save(h); err != nil {
		return nil, err
	}
	return h, nil
}

func (s *Store) List() ([]Host, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]Host, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.Dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var h Host
		if err := json.Unmarshal(b, &h); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (s *Store) save(h *Host) error {
	b, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.Dir, h.ID+".json")
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
