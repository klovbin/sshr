package sshcmd

import (
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"sshr.dev/internal/hosts"
	"sshr.dev/internal/vault"
)

// The tests of the runner were written against the Store of app, Store
// below gives them the same calls over an Env with the agent hook, the
// password manager and ssh config hooks stay in app and are tested there

const PasswordSaved = hosts.PasswordSaved

var (
	ErrKeyRequired   = hosts.ErrKeyRequired
	ErrKeyPassphrase = hosts.ErrKeyPassphrase
)

type Store struct {
	Dir   string
	Reuse *bool
}

func (s *Store) db() *hosts.Store {
	return &hosts.Store{Dir: s.Dir, Hooks: hosts.Hooks{AgentKey: PrepareAgentKey}}
}

func (s *Store) env() Env { return Env{Hosts: s.db(), Reuse: s.Reuse} }

func (s *Store) Add(in Host) (*Host, error)               { return s.db().Add(in) }
func (s *Store) Update(id string, in Host) (*Host, error) { return s.db().Update(id, in) }
func (s *Store) Import(in Host) (*Host, error)            { return s.db().Import(in) }
func (s *Store) Delete(id string) error                   { return s.db().Delete(id) }
func (s *Store) Find(query string) (*Host, error)         { return s.db().Find(query) }
func (s *Store) SetGateway(id, gw string) (*Host, error)  { return s.db().SetGateway(id, gw) }
func (s *Store) pubPath(h *Host) string                   { return s.db().PubPath(h) }
func (s *Store) upgradeSeals()                            { s.db().UpgradeSeals() }
func (s *Store) ConnectArgs(h *Host) ([]string, error)    { return s.env().ConnectArgs(h) }
func (s *Store) DirectArgs(h *Host) ([]string, error)     { return s.env().DirectArgs(h) }
func (s *Store) JumpArgs(h *Host) ([]string, error)       { return s.env().JumpArgs(h) }

func (s *Store) CopyArgs(h *Host, send, legacy bool, sources []string, dest string) ([]string, error) {
	return s.env().CopyArgs(h, send, legacy, sources, dest)
}

func (s *Store) PlanSession(h *Host, o LaunchOptions) (*SessionPlan, error) {
	return s.env().PlanSession(h, o)
}

func (s *Store) RunRemote(h *Host, command string, stdin io.Reader, timeout time.Duration) (*RemoteResult, error) {
	return s.env().RunRemote(h, command, stdin, timeout)
}

func (s *Store) UploadImage(h *Host, data []byte, ext string, batch bool) (string, error) {
	return s.env().UploadImage(h, data, ext, batch)
}

// mockKeychain is the system keychain over the mock of go-keyring, app
// sets the real one, sshcmd alone has none
type mockKeychain struct{}

func (mockKeychain) Get(name string) (string, error) {
	v, err := keyring.Get("sshr", name)
	return v, notFound(err)
}
func (mockKeychain) Set(name, value string) error { return keyring.Set("sshr", name, value) }
func (mockKeychain) Delete(name string) error     { return notFound(keyring.Delete("sshr", name)) }

func notFound(err error) error {
	if errors.Is(err, keyring.ErrNotFound) {
		return vault.ErrSecretNotFound
	}
	return err
}

// useMockKeychain starts from a clean vault over the mock keychain
func useMockKeychain(t *testing.T) {
	t.Helper()
	keyring.MockInit()
	vault.SetKeychain(mockKeychain{})
	vault.ResetForTest(filepath.Join(t.TempDir(), ".lock"))
}
