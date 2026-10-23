package app

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// commandTarget binds a host allowed for commands to where it points, a
// host repointed on another device keeps its ID and loses the permission
func commandTarget(h *Host) string {
	sum := sha256.Sum256([]byte(destination(*h)))
	return hex.EncodeToString(sum[:16])
}

// ErrCommandsNotAllowed means commands from assistants and scripts are
// limited to listed hosts and this one is not listed
var ErrCommandsNotAllowed = errors.New("commands are not allowed on this host")

// CommandsAllowed tells whether assistants and scripts may run commands on
// h: every host when the list is not asked for, otherwise only a host
// allowed with sshr commands allow that still points where it did
func (s Settings) CommandsAllowed(h *Host) error {
	if !s.CommandsListedOnly {
		return nil
	}
	target, ok := s.CommandHosts[h.ID]
	switch {
	case !ok:
		return fmt.Errorf("%w (%s), allow it with sshr commands allow %s", ErrCommandsNotAllowed, h.Name, h.Name)
	case target != commandTarget(h):
		return fmt.Errorf("%w (%s), it points elsewhere since it was allowed, check it and allow it again with sshr commands allow %s", ErrCommandsNotAllowed, h.Name, h.Name)
	}
	return nil
}

// AllowCommands lists h as a host assistants and scripts may run commands
// on, for where it points now
func (s *Settings) AllowCommands(h *Host) {
	m := make(map[string]string, len(s.CommandHosts)+1)
	for k, v := range s.CommandHosts {
		m[k] = v
	}
	m[h.ID] = commandTarget(h)
	s.CommandHosts = m
}

// DenyCommands takes the host with id off the list
func (s *Settings) DenyCommands(id string) {
	m := make(map[string]string, len(s.CommandHosts))
	for k, v := range s.CommandHosts {
		if k != id {
			m[k] = v
		}
	}
	s.CommandHosts = m
}
