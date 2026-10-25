package main

import (
	"fmt"
	"os"
	"strings"

	"sshr.dev/internal/app"
)

// cmdCopy is sshr send and sshr get, scp with the host's own login
func cmdCopy(store *app.Store, send bool, args []string) {
	name := "get"
	usage := "Usage: sshr get [--legacy] <name or id> <remote path>... [--to <local folder>]"
	dest := "."
	if send {
		name = "send"
		usage = "Usage: sshr send [--legacy] <name or id> <local path>... [--to <remote folder>]"
		dest = ""
	}
	var rest []string
	legacy := false
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--legacy" || a == "-O":
			legacy = true
		case a == "--to" && i+1 < len(args):
			i++
			dest = args[i]
		case strings.HasPrefix(a, "--to="):
			dest = strings.TrimPrefix(a, "--to=")
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(1)
	}
	h := findHost(store, name, rest[0])
	sources := rest[1:]
	if send {
		for _, p := range sources {
			if _, err := os.Stat(p); err != nil {
				fatal(err)
			}
		}
	}
	scp, err := app.SCPPath()
	if err != nil {
		fatal(err)
	}
	scpArgs, err := store.CopyArgs(h, send, legacy, sources, dest)
	if err != nil {
		fatal(err)
	}
	code := run(h, scp, scpArgs...)
	if code != 0 && !legacy {
		// scp only says "Connection closed" when the server has no SFTP
		fmt.Fprintf(os.Stderr, "sshr: if %s has no SFTP subsystem, try again with --legacy (scp -O)\n", h.Name)
	}
	os.Exit(code)
}
