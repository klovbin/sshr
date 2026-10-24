package app

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"sshr.dev/internal/settings"
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
		hop, saved, err := s.env().resolveHop(part)
		if err != nil || !saved {
			b.WriteString(part)
			continue
		}
		s.writeTarget(b, hop, depth+1)
	}
}

// ErrCommandsNotAllowed means commands from assistants and scripts are
// limited to listed hosts and this one is not listed
var ErrCommandsNotAllowed = settings.ErrCommandsNotAllowed
