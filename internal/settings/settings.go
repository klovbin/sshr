// Package settings reads and saves ~/.sshr/settings.json: a save changes
// only the fields its holder changed, keys a newer sshr wrote are kept,
// the file never syncs
package settings

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"sshr.dev/internal/fileio"
	"sshr.dev/internal/record"
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
	// Vault is where the vault key lives: empty or "keychain" for the system
	// keychain, "passphrase" for a file wrapped with a passphrase (#98), off
	// by default, a forgotten passphrase loses every saved secret
	Vault string `json:"vault,omitempty"`
	// AuditLog keeps ~/.sshr/audit.jsonl, a record of every upload,
	// command and host change made through sshr mcp and sshr serve, off by
	// default: it is one more file that grows (up to six times AuditMaxMB) and
	// tells which servers were used when
	AuditLog bool `json:"audit_log,omitempty"`
	// AuditMaxMB is the size the log reaches before it moves to
	// audit.jsonl.1, 0 means 10
	AuditMaxMB int `json:"audit_max_mb,omitempty"`
	// AuditCommands is "full" to keep whole commands in the log, empty
	// keeps their length, first word and a keyed hash, a command may carry
	// a password
	AuditCommands string `json:"audit_commands,omitempty"`
	// CommandsListedOnly limits commands from sshr mcp and sshr serve to
	// the hosts in CommandHosts, off by default: every host stays usable
	// as before, on it one more step is needed for each new server
	CommandsListedOnly bool `json:"commands_listed_only,omitempty"`
	// CommandHosts are the hosts allowed with sshr commands allow, host ID
	// to a hash of where it pointed then, settings never sync so another
	// device cannot add a host here
	CommandHosts map[string]string `json:"command_hosts,omitempty"`
	// ConfirmCommands asks the user before every command from an assistant,
	// through a question the MCP client shows, off by default: a client
	// that cannot ask gets every command refused and the REST API refuses
	// commands, it has nobody to ask
	ConfirmCommands bool `json:"confirm_commands,omitempty"`

	// base is the file as Load read it, Save writes only
	// the fields that differ from it, copies of the value share it
	base *Settings
	// extra are the keys of the file this build does not know, format is
	// its "version", see record.go
	extra  map[string]json.RawMessage
	format int
}

// settingsFormat is the format of settings.json this build writes, a file
// without "version" is format 1
const settingsFormat = 1

var settingsKeys = record.JSONKeys(reflect.TypeOf(Settings{}))

// DefaultHealthInterval is how often the app checks the hosts when the
// check is on and the interval is not set
const DefaultHealthInterval = 5 * time.Minute

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

// Path is ~/.sshr/settings.json, the folder is made if needed
func Path() (string, error) {
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

// Load reads settings.json, the result remembers what was read,
// so Save can tell the fields changed by its holder from the ones
// another process saved meanwhile
func Load() (Settings, error) {
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
	// nil stays nil and an empty list stays empty, DeepEqual tells them
	// apart and would see a change nobody made
	if s.OPAccounts != nil {
		c.OPAccounts = make([]OPLinkedAccount, len(s.OPAccounts))
		copy(c.OPAccounts, s.OPAccounts)
	}
	if s.CommandHosts != nil {
		c.CommandHosts = make(map[string]string, len(s.CommandHosts))
		for k, v := range s.CommandHosts {
			c.CommandHosts[k] = v
		}
	}
	return c
}

func readSettings() (Settings, error) {
	s := Settings{Lang: "ru"}
	path, err := Path()
	if err != nil {
		return s, err
	}
	b, err := fileio.ReadFileShared(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return s, err
	}
	// the format first: a newer sshr may have changed the type of a known
	// field, the file must then read as newer and not as damaged, or a save
	// would replace it with defaults
	format, ferr := record.FormatOf(b)
	if err := json.Unmarshal(b, &s); err != nil && (ferr != nil || format <= settingsFormat) {
		return Settings{Lang: "ru"}, err
	}
	if ferr != nil {
		return Settings{Lang: "ru"}, ferr
	}
	s.format = format
	if s.extra, err = record.UnknownKeys(b, settingsKeys); err != nil {
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

// Save writes s, a value from Load writes only the fields
// its holder changed since, on top of the file as it is now, so the app
// that loaded settings at start does not undo a setting the CLI saved
// meanwhile, a value built from scratch is written whole
func Save(s Settings) error {
	path, err := Path()
	if err != nil {
		return err
	}
	settingsMu.Lock()
	defer settingsMu.Unlock()
	unlock, err := fileio.WaitLock(path+".lock", "saving settings", settingsLockWait)
	if err != nil {
		return err
	}
	defer unlock()
	out := s
	cur, curErr := readSettings()
	if curErr == nil && cur.format > settingsFormat {
		return fmt.Errorf("%w: settings.json was saved by a newer sshr (format %d), this one reads it but does not change it, update sshr to change settings", record.ErrNewerFormat, cur.format)
	}
	if s.base != nil && curErr == nil {
		// a damaged file is replaced by what the holder has
		out = cur
		mergeChanged(&out, s, *s.base)
	}
	// the keys a newer sshr wrote are kept as the file has them, whatever
	// the holder read
	if curErr == nil {
		out.extra = cur.extra
	}
	out.base = nil
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if b, err = record.AppendKeys(b, out.extra); err != nil {
		return err
	}
	// through a temp file, the app and the CLI may save at once and a torn
	// file would load as defaults
	if err := fileio.WriteFile(path, append(b, '\n'), 0o600); err != nil {
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
		if reflect.DeepEqual(sv.Field(i).Interface(), bv.Field(i).Interface()) {
			continue
		}
		if m, ok := sv.Field(i).Interface().(map[string]string); ok {
			// a map changes key by key, a denial saved by another process
			// meanwhile is not undone by an allow of another key here
			d.Field(i).Set(reflect.ValueOf(mergeKeys(d.Field(i).Interface().(map[string]string), m, bv.Field(i).Interface().(map[string]string))))
			continue
		}
		d.Field(i).Set(sv.Field(i))
	}
}

// mergeKeys applies to cur the keys that s added, changed or removed
// against base
func mergeKeys(cur, s, base map[string]string) map[string]string {
	out := make(map[string]string, len(cur)+len(s))
	for k, v := range cur {
		out[k] = v
	}
	for k, v := range s {
		if bv, ok := base[k]; !ok || bv != v {
			out[k] = v
		}
	}
	for k := range base {
		if _, ok := s[k]; !ok {
			delete(out, k)
		}
	}
	return out
}
