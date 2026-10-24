package app

import (
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"

	"sshr.dev/internal/settings"
)

// HostCommand is what runs on this machine before and after a session,
// see settings.HostCommand
type HostCommand = settings.HostCommand

// LocalCommandsOf is what to run around a session to h, nothing for a host
// that is not saved or has no commands, on says whether they run: the
// setting, or force when connect got --local-commands or
// --no-local-commands
func LocalCommandsOf(st Settings, h *Host, force *bool) (cmd HostCommand, on bool) {
	if h == nil || h.ID == "" {
		return HostCommand{}, false
	}
	on = st.LocalCommands
	if force != nil {
		on = *force
	}
	return st.HostCommands[h.ID], on
}

// RunLocalCommand runs command on this machine through the shell, with
// the terminal of sshr, the host is passed in SSHR_HOST_ID, SSHR_HOST_NAME,
// SSHR_HOST, SSHR_PORT and SSHR_USER, exit >= 0 is the exit code of the
// session in SSHR_EXIT for a command after it
func RunLocalCommand(command string, h *Host, exit int, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := shellCommand(command)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	cmd.Env = append(os.Environ(),
		"SSHR_HOST_ID="+h.ID,
		"SSHR_HOST_NAME="+envSafe(h.Name, runtime.GOOS == "windows"),
		"SSHR_HOST="+h.Host,
		"SSHR_PORT="+strconv.Itoa(effectivePort(h.Port)),
		"SSHR_USER="+h.User,
	)
	if exit >= 0 {
		cmd.Env = append(cmd.Env, "SSHR_EXIT="+strconv.Itoa(exit))
	}
	return cmd.Run()
}

// envSafe is a host name another sync device may have set, made safe for
// the environment of a local command: control characters are dropped (a
// NUL would stop the command from starting), on Windows the characters
// cmd.exe acts on in %SSHR_HOST_NAME% become _, the address, user and port
// are checked when a host is saved and need none of this
func envSafe(s string, windows bool) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r < 0x20 || r == 0x7f:
			return -1
		case windows && strings.ContainsRune(`&|<>^%"()!`, r):
			return '_'
		}
		return r
	}, s)
}
