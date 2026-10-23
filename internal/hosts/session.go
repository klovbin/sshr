package hosts

import "fmt"

// Remote session managers a host can attach to on connect
const (
	SessionTmux   = "tmux"
	SessionZellij = "zellij"
)

// SessionName is the remote session sshr creates or reattaches to
const SessionName = "sshr"

// checkSession accepts "", "tmux" or "zellij"
func checkSession(kind string) error {
	switch kind {
	case "", SessionTmux, SessionZellij:
		return nil
	}
	return fmt.Errorf("unknown session %q (expected tmux or zellij)", kind)
}
