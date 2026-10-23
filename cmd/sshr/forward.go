package main

import (
	"fmt"
	"os"
	"strings"

	"sshr.dev/internal/app"
)

const forwardUsage = `Usage:
  sshr forward <host>                              list saved forwards
  sshr forward add <host> <name> -L|-R|-D <spec>   save a forward
  sshr forward rm <host> <name>                    remove a forward`

// cmdForward lists, adds and removes the named port forwards of a host
func cmdForward(store *app.Store, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, forwardUsage)
		os.Exit(1)
	}
	switch args[0] {
	case "add":
		if len(args) != 5 {
			fmt.Fprintln(os.Stderr, forwardUsage)
			os.Exit(1)
		}
		h := findHost(store, "forward", args[1])
		f, err := app.ParseForward(strings.Join(args[2:], " "))
		if err != nil {
			fatal(err)
		}
		in := *h
		in.Forwards = append(append([]app.Forward(nil), h.Forwards...), f)
		if _, err := store.Update(h.ID, in); err != nil {
			fatal(err)
		}
		fmt.Printf("Added forward %s to %s\n", f, h.Name)
	case "rm", "remove":
		if len(args) != 3 {
			fmt.Fprintln(os.Stderr, forwardUsage)
			os.Exit(1)
		}
		h := findHost(store, "forward", args[1])
		in := *h
		in.Forwards = nil
		for _, f := range h.Forwards {
			if f.Name != args[2] {
				in.Forwards = append(in.Forwards, f)
			}
		}
		if len(in.Forwards) == len(h.Forwards) {
			fatal(fmt.Errorf("%s has no forward named %q", h.Name, args[2]))
		}
		if _, err := store.Update(h.ID, in); err != nil {
			fatal(err)
		}
		fmt.Printf("Removed forward %s from %s\n", args[2], h.Name)
	default:
		h := findHost(store, "forward", strings.Join(args, " "))
		if len(h.Forwards) == 0 {
			fmt.Printf("%s has no saved forwards. Add one with `sshr forward add %s <name> -L <spec>`\n", h.Name, h.Name)
			return
		}
		for _, f := range h.Forwards {
			fmt.Println(f)
		}
	}
}

// cmdTunnel keeps the host's forwards open without a shell (ssh -N) until
// Ctrl+C, with no names it opens all of them
func cmdTunnel(store *app.Store, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: sshr tunnel <host> [forward names...]")
		os.Exit(1)
	}
	h := findHost(store, "tunnel", args[0])
	names := args[1:]
	if len(names) == 0 {
		names = []string{"all"}
	}
	fs, err := app.FindForwards(h.Forwards, names)
	if err != nil {
		fatal(err)
	}
	if len(fs) == 0 {
		fatal(fmt.Errorf("%s has no saved forwards", h.Name))
	}
	plan, err := store.PlanSession(h, app.LaunchOptions{Forwards: fs, Tunnel: true})
	if err != nil {
		fatal(err)
	}
	for _, f := range fs {
		fmt.Printf("  %s\n", f)
	}
	fmt.Printf("Tunnel to %s is open, Ctrl+C to close\n", h.Name)
	cmd, cleanup, err := plan.Command()
	if err != nil {
		fatal(err)
	}
	os.Exit(runAttached(cmd, cleanup))
}

// findHost resolves a host query or exits with the usual message
func findHost(store *app.Store, cmd, query string) *app.Host {
	h, err := store.Find(query)
	if err != nil {
		findFailed(cmd, query, err)
	}
	return h
}
