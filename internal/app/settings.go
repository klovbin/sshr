package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"
)

// OPLinkedAccount is one 1Password account the user authorized in settings.
type OPLinkedAccount struct {
	Ref   string `json:"ref"`
	Email string `json:"email,omitempty"`
}

// Label is the account name shown in the UI.
func (a OPLinkedAccount) Label() string {
	if a.Email != "" {
		return a.Email
	}
	return a.Ref
}

// Settings is ~/.sshr/settings.json (language, etc.).
type Settings struct {
	Lang string `json:"lang"`
	// Mosh makes connect use mosh instead of plain ssh. Off by default: it
	// needs mosh-server and open UDP ports on the server, drops port/agent
	// forwarding and terminal images, and does not run natively on Windows.
	Mosh bool `json:"mosh"`
	// Reuse makes sessions to the same host share one connection
	// (ControlMaster), the second one opens at once with no new login, off
	// by default: one dropped connection drops every session on it, a
	// password is not asked again while the master is up, and Windows
	// OpenSSH has no ControlMaster
	Reuse bool `json:"reuse"`
	// OPVault is the 1Password vault new items are created in when a host
	// keeps its password in 1Password, empty means the account's default
	// vault
	OPVault string `json:"op_vault,omitempty"`
	// OPAccount is the default 1Password account for OP_ACCOUNT (url, email or uuid)
	OPAccount string `json:"op_account,omitempty"`
	// OPEmail is the human label for OPAccount (legacy; prefer OPAccounts)
	OPEmail string `json:"op_email,omitempty"`
	// OPAccounts are all linked 1Password accounts (user can add several)
	OPAccounts []OPLinkedAccount `json:"op_accounts,omitempty"`
	// MCPCommands lets AI assistants run commands on saved hosts through
	// sshr mcp, off by default: an assistant that can run commands on every
	// server can also break them, most clients ask before each tool call,
	// but that can be turned off on their side
	MCPCommands bool `json:"mcp_commands,omitempty"`
	// APICommands enables POST /v1/hosts/{host}/run in sshr serve, off by
	// default for the same reason as MCPCommands
	APICommands bool `json:"api_commands,omitempty"`
	// HealthCheck makes the app check every host now and then and show
	// whether it answers, off by default: each check is a connection the
	// server logs as closed before login, fail2ban counts them in its
	// ddos and aggressive modes, and the checks go out from this machine on their own
	HealthCheck bool `json:"health_check,omitempty"`
	// HealthInterval is the seconds between checks, 0 means 300, less
	// than 60 is raised to 60
	HealthInterval int `json:"health_interval,omitempty"`

	// base is the file as LoadSettings read it, SaveSettings writes only
	// the fields that differ from it, copies of the value share it
	base *Settings
}

// HealthEvery is the interval between checks of the hosts
func (s Settings) HealthEvery() time.Duration {
	switch {
	case s.HealthInterval <= 0:
		return DefaultHealthInterval
	case s.HealthInterval < 60:
		return time.Minute
	}
	return time.Duration(s.HealthInterval) * time.Second
}

func settingsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".sshr")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "settings.json"), nil
}

// LoadSettings reads settings.json, the result remembers what was read,
// so SaveSettings can tell the fields changed by its holder from the ones
// another process saved meanwhile
func LoadSettings() (Settings, error) {
	s, err := readSettings()
	read := cloneSettings(s)
	s.base = &read
	return s, err
}

// cloneSettings is a copy that shares no slice with s, a change made in
// place inside a list (AddOPAccount sets an email that way) must show as a
// difference against what was read
func cloneSettings(s Settings) Settings {
	c := s
	c.base = nil
	c.OPAccounts = append([]OPLinkedAccount(nil), s.OPAccounts...)
	return c
}

func readSettings() (Settings, error) {
	s := Settings{Lang: "ru"}
	path, err := settingsPath()
	if err != nil {
		return s, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return Settings{Lang: "ru"}, err
	}
		if s.Lang == "" {
			s.Lang = "ru"
		}
		s.NormalizeOPAccounts()
		return s, nil
	}

// NormalizeOPAccounts migrates legacy OPAccount/OPEmail into OPAccounts.
func (s *Settings) NormalizeOPAccounts() {
	if len(s.OPAccounts) == 0 && s.OPAccount != "" {
		s.OPAccounts = []OPLinkedAccount{{Ref: s.OPAccount, Email: s.OPEmail}}
	}
	for i := range s.OPAccounts {
		if s.OPAccounts[i].Ref == "" {
			s.OPAccounts[i].Ref = s.OPAccounts[i].Email
		}
	}
	if s.OPAccount == "" && len(s.OPAccounts) > 0 {
		s.OPAccount = s.OPAccounts[0].Ref
		s.OPEmail = s.OPAccounts[0].Email
	}
}

// HasOPAccount reports whether any 1Password account is linked.
func (s Settings) HasOPAccount() bool {
	return len(s.OPAccounts) > 0 || s.OPAccount != ""
}

// AddOPAccount links an account (no-op if Ref already present). Sets it as default.
func (s *Settings) AddOPAccount(ref, email string) {
	s.NormalizeOPAccounts()
	for i, a := range s.OPAccounts {
		if a.Ref == ref || (email != "" && a.Email == email) {
			if email != "" {
				s.OPAccounts[i].Email = email
			}
			s.OPAccount = s.OPAccounts[i].Ref
			s.OPEmail = s.OPAccounts[i].Email
			return
		}
	}
	s.OPAccounts = append(s.OPAccounts, OPLinkedAccount{Ref: ref, Email: email})
	s.OPAccount = ref
	s.OPEmail = email
}

// RemoveOPAccount drops the account at i and fixes the default.
func (s *Settings) RemoveOPAccount(i int) {
	s.NormalizeOPAccounts()
	if i < 0 || i >= len(s.OPAccounts) {
		return
	}
	was := s.OPAccounts[i].Ref
	s.OPAccounts = append(s.OPAccounts[:i], s.OPAccounts[i+1:]...)
	if s.OPAccount == was {
		s.OPAccount, s.OPEmail = "", ""
		if len(s.OPAccounts) > 0 {
			s.OPAccount = s.OPAccounts[0].Ref
			s.OPEmail = s.OPAccounts[0].Email
		}
	}
}

// settingsLockWait is how long a save waits for another sshr process to
// finish its own, a settings save takes milliseconds
const settingsLockWait = 10 * time.Second

// settingsMu keeps two goroutines from updating the shared base at once
var settingsMu sync.Mutex

// SaveSettings writes s, a value from LoadSettings writes only the fields
// its holder changed since, on top of the file as it is now, so the app
// that loaded settings at start does not undo a setting the CLI saved
// meanwhile, a value built from scratch is written whole
func SaveSettings(s Settings) error {
	path, err := settingsPath()
	if err != nil {
		return err
	}
	settingsMu.Lock()
	defer settingsMu.Unlock()
	unlock, err := waitLock(path+".lock", "saving settings", settingsLockWait)
	if err != nil {
		return err
	}
	defer unlock()
	out := s
	if s.base != nil {
		// a damaged file is replaced by what the holder has
		if cur, err := readSettings(); err == nil {
			out = cur
			mergeChanged(&out, s, *s.base)
		}
	}
	out.base = nil
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	// through a temp file, the app and the CLI may save at once and a torn
	// file would load as defaults
	if err := WriteFileAtomic(path, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if s.base != nil {
		// the saved fields are now what the holder agrees with the file on,
		// the next save does not write them again over a newer change
		mergeChanged(s.base, cloneSettings(s), *s.base)
	}
	return nil
}

// mergeChanged copies into dst every field where s differs from base
func mergeChanged(dst *Settings, s, base Settings) {
	d, sv, bv := reflect.ValueOf(dst).Elem(), reflect.ValueOf(s), reflect.ValueOf(base)
	for i := 0; i < sv.NumField(); i++ {
		if !sv.Type().Field(i).IsExported() {
			continue
		}
		if !reflect.DeepEqual(sv.Field(i).Interface(), bv.Field(i).Interface()) {
			d.Field(i).Set(sv.Field(i))
		}
	}
}
