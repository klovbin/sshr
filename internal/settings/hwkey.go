package settings

import "slices"

// The modes of HardwareKey
const (
	HardwareKeyListed = "listed"
	HardwareKeyAll    = "all"
)

// HardwareKeyRequired tells whether the host with id may connect only
// with a key on a FIDO token
func (s Settings) HardwareKeyRequired(id string) bool {
	switch s.HardwareKey {
	case HardwareKeyAll:
		return true
	case HardwareKeyListed:
		return slices.Contains(s.HardwareKeyHosts, id)
	}
	return false
}

// RequireHardwareKey lists the host with id and turns the listed mode on
// when the requirement was off, "all" stays
func (s *Settings) RequireHardwareKey(id string) {
	if !slices.Contains(s.HardwareKeyHosts, id) {
		s.HardwareKeyHosts = append(slices.Clone(s.HardwareKeyHosts), id)
	}
	if s.HardwareKey == "" {
		s.HardwareKey = HardwareKeyListed
	}
}

// ReleaseHardwareKey takes the host with id off the list
func (s *Settings) ReleaseHardwareKey(id string) {
	s.HardwareKeyHosts = slices.DeleteFunc(slices.Clone(s.HardwareKeyHosts), func(v string) bool { return v == id })
}
