package app

import "fmt"

// SessionScript is the sh script that attaches to the remote session, or
// opens a plain login shell with a message when the tool is missing there,
// "" means no session
func SessionScript(kind string) string {
	var attach string
	switch kind {
	case SessionTmux:
		attach = "exec tmux new-session -A -s " + SessionName
	case SessionZellij:
		attach = "exec zellij attach --create " + SessionName
	default:
		return ""
	}
	return fmt.Sprintf(`if command -v %[1]s >/dev/null 2>&1; then %[2]s; fi
echo "sshr: %[1]s is not installed on this server, opening a plain shell" >&2
exec "${SHELL:-/bin/sh}" -l`, kind, attach)
}

// SessionCommand is SessionScript as one remote command for ssh, which
// hands it to the login shell, so it runs under sh even when that shell is
// fish
func SessionCommand(kind string) string {
	script := SessionScript(kind)
	if script == "" {
		return ""
	}
	return "sh -c " + shQuote(script)
}
