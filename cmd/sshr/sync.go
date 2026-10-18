package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"sshr.dev/internal/app"
	"sshr.dev/internal/syncclient"
)

const syncUsage = `Usage:
  sshr sync                              pull, then push what changed here
  sshr sync init --server <url> [--name <device>]
                                         start syncing, this machine is the first device
  sshr sync invite                       code for a new device to join with
  sshr sync join --server <url> [--name <device>] <code>
                                         ask to add this machine, shows its fingerprint
  sshr sync pending                      devices waiting for approval
  sshr sync approve <id|fingerprint>     add a waiting device after comparing fingerprints
  sshr sync pull [--accept-reset]        only take changes from other devices
  sshr sync push                         same as sshr sync
  sshr sync status                       server, devices, state fingerprint
  sshr sync remove-device <id|fingerprint>
                                         take a device out, the vault key changes
  sshr sync leave [--force]              stop syncing here, hosts stay`

// cmdSync runs the sync subcommands
func cmdSync(store *app.Store, args []string) {
	dir, err := syncclient.DefaultDir()
	if err != nil {
		fatal(err)
	}
	c := &syncclient.Client{Store: store, Dir: dir, Log: os.Stdout, KeyPrefix: os.Getenv("SSHR_SYNC_KEYS")}
	sub := "push"
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	var server, name string
	var rest []string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--server" && i+1 < len(args):
			i++
			server = args[i]
		case a == "--name" && i+1 < len(args):
			i++
			name = args[i]
		case a == "--accept-reset":
			c.AcceptReset = true
		case strings.HasPrefix(a, "-"):
			fmt.Fprintln(os.Stderr, syncUsage)
			os.Exit(1)
		default:
			rest = append(rest, a)
		}
	}
	switch sub {
	case "init":
		if server == "" {
			fatal(fmt.Errorf("sshr sync init needs --server <url>"))
		}
		if err := c.Init(server, name); err != nil {
			fatal(err)
		}
		code, _ := c.Invite()
		fmt.Printf("Sync is on, this is the first device\nTo add another one run there:\n  sshr sync join --server %s %s\n", server, code)
	case "invite":
		code, err := c.Invite()
		if err != nil {
			fatal(err)
		}
		st, _ := c.Status()
		fmt.Printf("On the new device run:\n  sshr sync join --server %s %s\n", st.Server, code)
	case "join":
		if server == "" || len(rest) != 1 {
			fatal(fmt.Errorf("sshr sync join --server <url> <code>"))
		}
		fp, err := c.Join(server, rest[0], name)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("Asked to join, fingerprint of this device:\n  %s\nOn a device that is already in, run sshr sync approve and check that it shows the same fingerprint, then run sshr sync pull here\n", fp)
	case "pending":
		ds, err := c.Pending()
		if err != nil {
			fatal(err)
		}
		if len(ds) == 0 {
			fmt.Println("No devices are waiting")
		}
		for _, d := range ds {
			fmt.Printf("%s  %s  %s\n", d.ID[:8], syncclient.Fingerprint(d.SignPub), d.Name)
		}
	case "approve":
		if len(rest) != 1 {
			fatal(fmt.Errorf("sshr sync approve <id|fingerprint>, see sshr sync pending"))
		}
		d, err := c.Approve(rest[0])
		if err != nil {
			fatal(err)
		}
		fmt.Printf("Added %s (%s)\n", d.Name, syncclient.Fingerprint(d.SignPub))
	case "pull":
		if err := c.Pull(); err != nil {
			fatal(err)
		}
		fmt.Println("Up to date")
	case "push", "now":
		if err := c.Push(); err != nil {
			fatal(err)
		}
		fmt.Println("Synced")
	case "status":
		st, err := c.Status()
		if err != nil {
			fatal(err)
		}
		fmt.Printf("server       %s\naccount      %s\nthis device  %s %s (%s)\n", st.Server, st.Account, st.Device[:8], st.Name, st.Fingerprint)
		if st.Waiting {
			fmt.Println("state        waiting for approval")
			return
		}
		fmt.Printf("state        change %d, %s (the same on every device that is up to date)\n", st.Counter, st.State)
		if !st.LastSync.IsZero() {
			fmt.Printf("last sync    %s\n", st.LastSync.Local().Format(time.DateTime))
		}
		fmt.Println("devices")
		for _, d := range st.Devices {
			fmt.Printf("  %s  %s  %s\n", d.ID[:8], syncclient.Fingerprint(d.SignPub), d.Name)
		}
	case "remove-device":
		if len(rest) != 1 {
			fatal(fmt.Errorf("sshr sync remove-device <id|fingerprint>"))
		}
		d, err := c.RemoveDevice(rest[0])
		if err != nil {
			fatal(err)
		}
		fmt.Printf("Removed %s, the vault key was changed, what it already downloaded it keeps\n", d.Name)
	case "leave":
		if err := c.Leave(len(rest) == 1 && rest[0] == "--force"); err != nil {
			fatal(err)
		}
		fmt.Println("Sync is off on this machine, the hosts stay")
	default:
		fmt.Fprintln(os.Stderr, syncUsage)
		os.Exit(1)
	}
}
