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
  sshr sync init --backend s3 --endpoint <url> --bucket <name> [--prefix <dir>]
                 [--region <r>] --key-id <id> [--name <device>]
                                         keep the account in an S3 bucket instead,
                                         the secret key comes from SSHR_S3_SECRET or a prompt
  sshr sync invite                       code for a new device to join with
  sshr sync join --server <url> [--name <device>] <code>
                                         ask to add this machine, shows its fingerprint,
                                         an S3 or WebDAV account takes the flags of init instead of --server
  sshr sync pending                      devices waiting for approval
  sshr sync approve <id|fingerprint>     add a waiting device after comparing fingerprints
  sshr sync pull [--accept-reset]        only take changes from other devices
  sshr sync push                         same as sshr sync
  sshr sync status                       server, devices, state fingerprint
  sshr sync remove-device <id|fingerprint>
                                         take a device out, the vault key changes
  sshr sync init --backend webdav --url <folder> --user <name> [--name <device>]
                                         keep the account in a WebDAV folder (Nextcloud),
                                         the password from SSHR_WEBDAV_PASSWORD or a prompt
  sshr sync store-key --key-id <id>      a new key of the S3 bucket of this account,
                                         the secret from SSHR_S3_SECRET or a prompt
  sshr sync store-key [--user <name>]    a new password of the WebDAV folder
  sshr sync leave [--force]              stop syncing here, hosts stay`

// cmdSync runs the sync subcommands
func cmdSync(store *app.Store, args []string) {
	dir, err := syncclient.DefaultDir()
	if err != nil {
		fatal(err)
	}
	c := &syncclient.Client{Store: store.Hosts(), Dir: dir, Log: os.Stdout, KeyPrefix: os.Getenv("SSHR_SYNC_KEYS"),
		OpenBackend: openStore}
	sub := "push"
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	var server, name string
	var rest []string
	var sf storeFlags
	for i := 0; i < len(args); i++ {
		if ok, err := sf.take(args, &i); err != nil {
			fatal(err)
		} else if ok {
			continue
		}
		switch a := args[i]; {
		case a == "--server" || a == "--name":
			v, err := flagValue(args, &i)
			if err != nil {
				fatal(err)
			}
			if a == "--server" {
				server = v
			} else {
				name = v
			}
		case a == "--accept-reset":
			c.AcceptReset = true
		case strings.HasPrefix(a, "-"):
			fmt.Fprintln(os.Stderr, syncUsage)
			os.Exit(1)
		default:
			rest = append(rest, a)
		}
	}
	if sf.given && sub != "init" && sub != "join" && sub != "store-key" {
		fatal(fmt.Errorf("--backend and the S3 flags are for sshr sync init and join, later runs read them from the sync state"))
	}
	switch sub {
	case "init":
		if err := c.CheckFree(); err != nil {
			fatal(err)
		}
		if server, err = sf.setup(c, server); err != nil {
			fatal(err)
		}
		if server == "" {
			fatal(fmt.Errorf("sshr sync init needs --server <url>, --backend s3 or --backend webdav"))
		}
		if err := c.Init(server, name); err != nil {
			fatal(err)
		}
		code, err := c.Invite()
		if err != nil {
			fatal(fmt.Errorf("sync is on, but the invite code is not ready, run sshr sync invite: %v", err))
		}
		flags, err := joinFlags(server, c.BackendRef)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("Sync is on, this is the first device\nTo add another one run there:\n  sshr sync join %s %s\n", flags, code)
	case "invite":
		code, err := c.Invite()
		if err != nil {
			fatal(err)
		}
		st, err := c.Status()
		if err != nil {
			fatal(err)
		}
		flags, err := joinFlags(st.Server, st.Backend)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("On the new device run:\n  sshr sync join %s %s\n", flags, code)
	case "join":
		if (server == "" && sf.backend == "") || len(rest) != 1 {
			fatal(fmt.Errorf("sshr sync join --server <url> <code>, or the --backend flags sshr sync invite prints"))
		}
		if err := c.CheckFree(); err != nil {
			fatal(err)
		}
		if server, err = sf.setup(c, server); err != nil {
			fatal(err)
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
		leftOut(c)
	case "push", "now":
		if err := c.Push(); err != nil {
			fatal(err)
		}
		fmt.Println("Synced")
		leftOut(c)
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
		if ref, err := c.StoreRef(); err == nil && ref != nil && ref.Kind == "webdav" {
			fmt.Println("This account is in a WebDAV folder and the removed device still knows the password, it can delete files and stop the sync\nChange the password (in Nextcloud make a new app password and delete the old one), then run on every device that stays:\n  sshr sync store-key")
		} else if err == nil && ref != nil {
			fmt.Println("This account is in a bucket and the removed device still holds the bucket key, it can delete objects and stop the sync\nMake a new key for the bucket, delete the old one, then run on every device that stays:\n  sshr sync store-key --key-id <new key id>")
		}
	case "store-key":
		if err := sf.replaceKey(c); err != nil {
			fatal(err)
		}
		fmt.Println("The new bucket key is saved on this machine, delete the old key once every device has the new one")
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

// leftOut says which hosts the run did not sync and exits 1, a sync that
// skipped hosts must not read as a full one
func leftOut(c *syncclient.Client) {
	if len(c.LeftOut) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "sshr: %s left out of this sync, the lines above say why\n", plural(len(c.LeftOut), "host"))
	os.Exit(1)
}
