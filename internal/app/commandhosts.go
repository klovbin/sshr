package app

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// CommandTarget binds a host allowed for commands to where it points: its
// own destination and the destinations of the saved hosts its jump and
// gateway go through, a host or a hop repointed on another device keeps
// its ID and the host loses the permission
func (s *Store) CommandTarget(h *Host) string {
	var b strings.Builder
	s.writeTarget(&b, h, 0)
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:16])
}

func (s *Store) writeTarget(b *strings.Builder, h *Host, depth int) {
	b.WriteString(destination(*h))
	if depth >= maxJumpDepth {
		return
	}
	for _, part := range SplitJump(h.Jump + "," + h.Gateway) {
		b.WriteString("\x00hop\x00")
		hop, saved, err := s.resolveHop(part)
		if err != nil || !saved {
			b.WriteString(part)
			continue
		}
		s.writeTarget(b, hop, depth+1)
	}
}

// ErrCommandsNotAllowed means commands from assistants and scripts are
// limited to listed hosts and this one is not listed
var ErrCommandsNotAllowed = errors.New("commands are not allowed on this host")

// CommandsAllowed tells whether assistants and scripts may run commands on
// h, target is Store.CommandTarget of it: every host when the list is not
// asked for, otherwise only a host allowed with sshr commands allow that
// still points where it did
func (s Settings) CommandsAllowed(h *Host, target string) error {
	if !s.CommandsListedOnly {
		return nil
	}
	allowed, ok := s.CommandHosts[h.ID]
	switch {
	case !ok:
		return fmt.Errorf("%w (%s), allow it with sshr commands allow %s", ErrCommandsNotAllowed, h.Name, h.Name)
	case allowed != target:
		return fmt.Errorf("%w (%s), it points elsewhere since it was allowed, check it and allow it again with sshr commands allow %s", ErrCommandsNotAllowed, h.Name, h.Name)
	}
	return nil
}

// AllowCommands lists h as a host assistants and scripts may run commands
// on, for target, where it points now
func (s *Settings) AllowCommands(h *Host, target string) {
	m := make(map[string]string, len(s.CommandHosts)+1)
	for k, v := range s.CommandHosts {
		m[k] = v
	}
	m[h.ID] = target
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
