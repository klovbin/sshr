package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

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
	// OPAccount is the 1Password account (url, email or uuid) chosen when the
	// user connects CLI integration in settings, empty lets op pick
	OPAccount string `json:"op_account,omitempty"`
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

func LoadSettings() (Settings, error) {
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
	return s, nil
}

func SaveSettings(s Settings) error {
	path, err := settingsPath()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}
