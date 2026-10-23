package settings

import (
	"errors"
	"fmt"
)

// ErrCommandsNotAllowed means commands from assistants and scripts are
// limited to listed hosts and this one is not listed
var ErrCommandsNotAllowed = errors.New("commands are not allowed on this host")

// CommandsAllowed tells whether assistants and scripts may run commands on
// the host with id and name, target is Store.CommandTarget of it: every
// host when the list is not asked for, otherwise only a host allowed with
// sshr commands allow that still points where it did, settings know no
// Host so they can live apart from the hosts
func (s Settings) CommandsAllowed(id, name, target string) error {
	if !s.CommandsListedOnly {
		return nil
	}
	allowed, ok := s.CommandHosts[id]
	switch {
	case !ok:
		return fmt.Errorf("%w (%s), allow it with sshr commands allow %s", ErrCommandsNotAllowed, name, name)
	case allowed != target:
		return fmt.Errorf("%w (%s), it points elsewhere since it was allowed, check it and allow it again with sshr commands allow %s", ErrCommandsNotAllowed, name, name)
	}
	return nil
}

// AllowCommands lists the host with id as a host assistants and scripts
// may run commands on, for target, where it points now
func (s *Settings) AllowCommands(id, target string) {
	m := make(map[string]string, len(s.CommandHosts)+1)
	for k, v := range s.CommandHosts {
		m[k] = v
	}
	m[id] = target
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
