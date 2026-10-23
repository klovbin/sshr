package app

import (
	"fmt"
	"path/filepath"
	"strings"
)

// checkOPRef refuses anything that is not an op:// secret reference
func checkOPRef(ref string) error {
	rest, ok := strings.CutPrefix(ref, "op://")
	if !ok || strings.Count(rest, "/") < 2 {
		return fmt.Errorf("%q is not a 1Password secret reference, expected op://vault/item/field", ref)
	}
	return nil
}

// checkBWRef refuses what bw would read as an option or cannot be an item
func checkBWRef(ref string) error {
	if ref == "" || strings.HasPrefix(ref, "-") || strings.ContainsAny(ref, "\r\n") {
		return fmt.Errorf("%q is not a Bitwarden item, give its ID (bw list items) or a name that finds one item", ref)
	}
	return nil
}

// checkAgent trims the agent of h and refuses one that is not system,
// 1password or the full path of an agent socket
func checkAgent(h *Host) error {
	h.Agent = strings.TrimSpace(h.Agent)
	if h.Agent != "" && h.Agent != "system" && h.Agent != AgentOnePassword && !filepath.IsAbs(ExpandHome(h.Agent)) && !strings.HasPrefix(h.Agent, `\\.\pipe\`) {
		return fmt.Errorf("agent %q: use system, 1password or the full path of the agent socket", h.Agent)
	}
	return nil
}
