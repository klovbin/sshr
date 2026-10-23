package app

import (
	"sshr.dev/internal/health"
	"sshr.dev/internal/settings"
)

// The checks of hosts live in package health, these names keep the front
// ends working as before

// Health is the result of one check
type Health = health.Health

// HostKey is what the server showed as its key
type HostKey = health.HostKey

// The states of a check and of a host key
const (
	HealthUp      = health.HealthUp
	HealthDown    = health.HealthDown
	HealthNotSSH  = health.HealthNotSSH
	HealthUnknown = health.HealthUnknown
	HealthTimeout = health.HealthTimeout
	KeyKnown      = health.KeyKnown
	KeyChanged    = health.KeyChanged
	KeyUnknown    = health.KeyUnknown
)

// DefaultHealthInterval is how often the app checks the hosts when the
// check is on and the interval is not set
const DefaultHealthInterval = settings.DefaultHealthInterval

// CheckHealth checks one host, see health.CheckHealth
func CheckHealth(h *Host) Health { return health.CheckHealth(h) }

// CheckHealthAll checks the hosts eight at a time
func CheckHealthAll(list []Host) map[string]Health { return health.CheckHealthAll(list) }

// CheckHostKey reads the key a host shows, see health.CheckHostKey
func CheckHostKey(h *Host) HostKey { return health.CheckHostKey(h) }

// CheckHostKeyAll reads the keys of the hosts eight at a time
func CheckHostKeyAll(list []Host) map[string]HostKey { return health.CheckHostKeyAll(list) }
