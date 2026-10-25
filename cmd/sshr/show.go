package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"sshr.dev/internal/app"
)

// cmdShow prints one host and the ssh command sshr connect runs for it,
// secrets are never part of either, a password reaches ssh through the
// askpass socket and not the command line
func cmdShow(store *app.Store, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: sshr show <name or id>")
		os.Exit(1)
	}
	query := strings.Join(args, " ")
	h, err := store.Find(query)
	if err != nil {
		findFailed("show", query, err)
	}
	argv, err := connectCommand(store, h)
	if err != nil {
		fatal(err)
	}
	writeShow(os.Stdout, h, argv, time.Now())
}

// connectCommand is the plain ssh command of sshr connect for h, without
// forwards and mosh, the direct way of a host with a gateway, the gateway
// row says when it is used
func connectCommand(store *app.Store, h *app.Host) ([]string, error) {
	opts, err := store.DirectArgs(h)
	if err != nil {
		return nil, err
	}
	argv := append([]string{"ssh"}, opts...)
	if h.Session != "" {
		return append(argv, "-t", "--", h.Dest(), app.SessionCommand(h.Session)), nil
	}
	return append(argv, "--", h.Dest()), nil
}

func writeShow(w io.Writer, h *app.Host, argv []string, now time.Time) {
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(w, "%-15s %s\n", k, v)
		}
	}
	row("name", h.Name)
	row("id", h.ID)
	row("address", fmt.Sprintf("%s@%s:%d", h.User, h.Host, h.Port))
	row("login", h.AuthLabel())
	if typ := app.HardwareKeyFile(app.ExpandHome(h.Key)); typ != "" {
		row("key file", h.Key+" (hardware key, "+typ+")")
	} else {
		row("key file", h.Key)
	}
	row("agent", h.Agent)
	row("jump hosts", h.Jump)
	row("gateway", h.Gateway)
	row("session", h.Session)
	for _, f := range h.Forwards {
		row("forward", f.Name+" -"+f.Kind+" "+f.Spec)
	}
	row("tags", strings.Join(h.Tags, ", "))
	if !h.CreatedAt.IsZero() {
		row("added", h.CreatedAt.Local().Format(time.DateTime))
	}
	row("last connect", app.Ago(h.LastConnected, now))
	fmt.Fprintln(w, "\nsshr connect runs:")
	fmt.Fprintln(w, "  "+shellLine(argv))
}

// shellLine quotes each argument for a POSIX shell, so the line can be
// copied and run as it is
func shellLine(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if a != "" && strings.Trim(a, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%+=:,./_-") == "" {
			out[i] = a
			continue
		}
		out[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(out, " ")
}
