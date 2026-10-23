package app

import (
	"encoding/json"
	"reflect"
	"time"

	"sshr.dev/internal/hosts"
	"sshr.dev/internal/record"
)

// The hosts and their files live in package hosts, these names keep the
// front ends and the code that runs ssh working as before

// Host is one SSH target, see hosts.Host
type Host = hosts.Host

// Forward is a named port forward of a host
type Forward = hosts.Forward

// HostSummary is a host without its secrets
type HostSummary = hosts.HostSummary

// AmbiguousError means a query matched several hosts
type AmbiguousError = hosts.AmbiguousError

// Password and key modes, sessions, see package hosts
const (
	PasswordSaved       = hosts.PasswordSaved
	PasswordAsk         = hosts.PasswordAsk
	PasswordOnePassword = hosts.PasswordOnePassword
	PasswordBitwarden   = hosts.PasswordBitwarden
	KeyVault            = hosts.KeyVault
	KeyAgent            = hosts.KeyAgent
	KeyOnePassword      = hosts.KeyOnePassword
	KeyBitwarden        = hosts.KeyBitwarden
	AgentOnePassword    = hosts.AgentOnePassword
	SessionTmux         = hosts.SessionTmux
	SessionZellij       = hosts.SessionZellij
	SessionName         = hosts.SessionName
)

// The errors of the hosts, the same values as in package hosts
var (
	ErrHostEmpty        = hosts.ErrHostEmpty
	ErrUserRequired     = hosts.ErrUserRequired
	ErrNotFound         = hosts.ErrNotFound
	ErrPortInvalid      = hosts.ErrPortInvalid
	ErrPasswordRequired = hosts.ErrPasswordRequired
	ErrKeyRequired      = hosts.ErrKeyRequired
	ErrChanged          = hosts.ErrChanged
	ErrKeyPassphrase    = hosts.ErrKeyPassphrase
	ErrNewerFormat      = hosts.ErrNewerFormat
)

// ParsePort reads a TCP port
func ParsePort(s string) (int, error) { return hosts.ParsePort(s) }

// SplitJump turns "a,b" into ["a", "b"]
func SplitJump(spec string) []string { return hosts.SplitJump(spec) }

// ParseHop reads a free-form jump hop
func ParseHop(spec string) (*Host, error) { return hosts.ParseHop(spec) }

// ExpandHome turns a leading ~ into the home folder
func ExpandHome(path string) string { return hosts.ExpandHome(path) }

// CheckPrivateKey refuses a key file that is not a private key
func CheckPrivateKey(path string) error { return hosts.CheckPrivateKey(path) }

// FromOtherDevice prepares a host synced from another device
func FromOtherDevice(in Host, local *Host) (Host, []string) { return hosts.FromOtherDevice(in, local) }

// SortRecent puts the hosts connected to last first
func SortRecent(list []Host) { hosts.SortRecent(list) }

// Ago says how long ago t was
func Ago(t *time.Time, now time.Time) string { return hosts.Ago(t, now) }

// ParseDestination reads user@host[:port] into a host that is not saved
func ParseDestination(s string) (Host, error) { return hosts.ParseDestination(s) }

// ParseForward reads one port forward
func ParseForward(s string) (Forward, error) { return hosts.ParseForward(s) }

// ParseForwards reads port forwards, one per line
func ParseForwards(text string) ([]Forward, error) { return hosts.ParseForwards(text) }

// FormatForwards writes port forwards one per line
func FormatForwards(fs []Forward) string { return hosts.FormatForwards(fs) }

// FindForwards picks saved forwards by name
func FindForwards(fs []Forward, names []string) ([]Forward, error) {
	return hosts.FindForwards(fs, names)
}

// SplitTags reads tags typed as "prod, db" or "prod db"
func SplitTags(s string) []string { return hosts.SplitTags(s) }

// CleanTags normalizes tags
func CleanTags(in []string) ([]string, error) { return hosts.CleanTags(in) }

// Filter keeps the hosts that match query
func Filter(list []Host, query string) []Host { return hosts.Filter(list, query) }

// HostPayloadJSON is a host as it syncs
func HostPayloadJSON(h Host) ([]byte, error) { return hosts.HostPayloadJSON(h) }

// HostFromPayloadJSON reads a host as it syncs
func HostFromPayloadJSON(b []byte) (Host, error) { return hosts.HostFromPayloadJSON(b) }

// RecordExtra reads the keys of the JSON object b that are no field of the
// struct type typ and its "version", for a file of another package that
// keeps what a newer sshr wrote
func RecordExtra(b []byte, typ reflect.Type) (map[string]json.RawMessage, int, error) {
	return record.Extra(b, typ)
}

// AppendRecordKeys writes the kept keys extra into the JSON object b,
// written by json.MarshalIndent with two spaces
func AppendRecordKeys(b []byte, extra map[string]json.RawMessage) ([]byte, error) {
	return record.AppendKeys(b, extra)
}

func destination(h Host) string              { return hosts.Destination(h) }
func effectivePort(p int) int                { return hosts.EffectivePort(p) }
func checkAddress(a string) error            { return hosts.CheckAddress(a) }
func normalizeJump(s string) (string, error) { return hosts.NormalizeJump(s) }
func checkAgent(h *Host) error               { return hosts.CheckAgent(h) }
func unlockSaved(h *Host) error              { return hosts.UnlockSaved(h) }

// hostStore is the host store of package hosts
type hostStore = hosts.Store

// hostHooks are the steps of a change that run programs
type hostHooks = hosts.Hooks
