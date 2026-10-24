package main

import (
	"fmt"
	"os"
	"slices"

	"sshr.dev/internal/app"
)

const hwkeyUsage = `Usage: sshr hwkey status
       sshr hwkey require <host>... | --all
       sshr hwkey off [<host>...]`

// cmdHwkey sets which hosts connect only with a key on a FIDO token, the
// list lives in settings.json and never syncs
func cmdHwkey(store *app.Store, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, hwkeyUsage)
		os.Exit(1)
	}
	st, err := app.LoadSettings()
	if err != nil {
		fatal(err)
	}
	switch {
	case args[0] == "status" && len(args) == 1:
		hwkeyStatus(store, st)
		return
	case args[0] == "require" && len(args) == 2 && args[1] == "--all":
		st.HardwareKey = app.HardwareKeyAll
	case args[0] == "require" && len(args) > 1:
		for _, name := range args[1:] {
			st.RequireHardwareKey(findHost(store, "hwkey require", name).ID)
		}
	case args[0] == "off" && len(args) == 1:
		st.HardwareKey, st.HardwareKeyHosts = "", nil
	case args[0] == "off":
		for _, name := range args[1:] {
			st.ReleaseHardwareKey(findHost(store, "hwkey off", name).ID)
		}
	default:
		fmt.Fprintln(os.Stderr, hwkeyUsage)
		os.Exit(1)
	}
	if err := app.SaveSettings(st); err != nil {
		fatal(err)
	}
	hwkeyStatus(store, st)
}

// hwkeyStatus prints the mode and every host under it, with whether its
// login is a key on a token now, a host that is not would be refused at
// connect
func hwkeyStatus(store *app.Store, st app.Settings) {
	switch st.HardwareKey {
	case app.HardwareKeyAll:
		fmt.Println("every host connects only with a key on a hardware token")
	case app.HardwareKeyListed:
		fmt.Println("the hosts below connect only with a key on a hardware token")
	default:
		fmt.Println("no host needs a hardware key, sshr hwkey require <host> asks for one")
		return
	}
	list, err := store.List()
	if err != nil {
		fatal(err)
	}
	for i := range list {
		h := &list[i]
		if !st.HardwareKeyRequired(h.ID) {
			continue
		}
		state := "ready, its key is on a token"
		if err := app.CheckHardwareKey(h); err != nil {
			state = "refused at connect, " + err.Error()
		}
		fmt.Printf("  %s (%s): %s\n", h.Name, h.Dest(), state)
	}
	if st.HardwareKey == app.HardwareKeyListed {
		for _, id := range st.HardwareKeyHosts {
			if !slices.ContainsFunc(list, func(h app.Host) bool { return h.ID == id }) {
				fmt.Printf("  %s: no such host here, sshr hwkey off drops all\n", id)
			}
		}
	}
}
