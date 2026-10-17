package app

import (
	"path/filepath"
	"strings"
)

// HostSummary is what other programs (MCP, the REST API) may know about a
// host, no passwords, keys or references to them
type HostSummary struct {
	Name     string   `json:"name"`
	ID       string   `json:"id"`
	Address  string   `json:"address"`
	User     string   `json:"user"`
	Port     int      `json:"port"`
	Auth     string   `json:"auth"`
	Jump     string   `json:"jump,omitempty"`
	Session  string   `json:"session,omitempty"`
	Forwards []string `json:"forwards,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

// AuthLabel says in words how h logs in
func (h *Host) AuthLabel() string {
	switch {
	case h.Key != "":
		return "key file"
	case h.KeyMode == KeyVault:
		return "key stored in sshr"
	case h.KeyMode == KeyAgent:
		return "key from an ssh agent"
	case managerName(h.KeyMode) != "":
		return "key in " + managerName(h.KeyMode)
	case h.PasswordMode == PasswordSaved:
		return "saved password"
	case managerName(h.PasswordMode) != "":
		return "password in " + managerName(h.PasswordMode)
	case h.PasswordMode == PasswordAsk:
		return "password asked every time (not usable without a terminal)"
	}
	return "ssh config or agent"
}

// AuthShort is the same in a word or two, for the AUTH column of sshr list
func (h *Host) AuthShort() string {
	switch {
	case h.Key != "":
		return filepath.Base(h.Key)
	case h.KeyMode == KeyVault:
		return "key (sshr)"
	case h.KeyMode == KeyAgent:
		agent := h.Agent
		if agent == "" {
			agent = "system"
		}
		return "agent (" + agent + ")"
	case managerName(h.KeyMode) != "":
		return "key (" + strings.ToLower(managerName(h.KeyMode)) + ")"
	case h.PasswordMode == PasswordSaved:
		return "password"
	case managerName(h.PasswordMode) != "":
		return "password (" + strings.ToLower(managerName(h.PasswordMode)) + ")"
	case h.PasswordMode == PasswordAsk:
		return "ask"
	}
	return "-"
}

// Summary is h without its secrets
func (h *Host) Summary() HostSummary {
	sum := HostSummary{Name: h.Name, ID: h.ID, Address: h.Host, User: h.User, Port: h.Port, Auth: h.AuthLabel(), Jump: h.Jump, Session: h.Session, Tags: h.Tags}
	for _, f := range h.Forwards {
		sum.Forwards = append(sum.Forwards, f.String())
	}
	return sum
}
