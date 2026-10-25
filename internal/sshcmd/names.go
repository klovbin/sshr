package sshcmd

import (
	"sshr.dev/internal/health"
	"sshr.dev/internal/hosts"
	"sshr.dev/internal/pwmgr"
	"sshr.dev/internal/settings"
	"sshr.dev/internal/vault"
)

// The short names below are the ones the runner was written with in app,
// they point at the packages that own them

type (
	Host           = hosts.Host
	Forward        = hosts.Forward
	AmbiguousError = hosts.AmbiguousError
)

const (
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
	HealthDown          = health.HealthDown
)

var (
	SessionName   = hosts.SessionName
	ErrSealBroken = vault.ErrSealBroken
)

func SplitJump(spec string) []string           { return hosts.SplitJump(spec) }
func ParseHop(spec string) (*Host, error)      { return hosts.ParseHop(spec) }
func ExpandHome(path string) string            { return hosts.ExpandHome(path) }
func CheckHealth(h *Host) health.Health        { return health.CheckHealth(h) }
func normalizeJump(s string) (string, error)   { return hosts.NormalizeJump(s) }
func destination(h Host) string                { return hosts.Destination(h) }
func checkAddress(a string) error              { return hosts.CheckAddress(a) }
func checkAgent(h *Host) error                 { return hosts.CheckAgent(h) }
func unlockSaved(h *Host) error                { return hosts.UnlockSaved(h) }
func opRead(ref string) ([]byte, error)        { return pwmgr.OPRead(ref) }
func opReadKey(ref string) ([]byte, error)     { return pwmgr.OPReadKey(ref) }
func bwPassword(ref string) ([]byte, error)    { return pwmgr.BWPassword(ref) }
func bwKey(ref string) ([]byte, string, error) { return pwmgr.BWKey(ref) }
func LoadSettings() (settings.Settings, error) { return settings.Load() }
func unsealFor(blob, hostID, field, dest string) ([]byte, error) {
	return vault.UnsealFor(blob, hostID, field, dest)
}
