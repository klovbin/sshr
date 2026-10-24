package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"sshr.dev/internal/app"
	"sshr.dev/internal/supastore"
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
  sshr sync approve <id|fingerprint>     add a waiting device after comparing fingerprints,
                                         on the primary device
  sshr sync primary <id|fingerprint> [--yes]
                                         hand the primary role on, only the primary
                                         device adds and removes devices
  sshr sync pull [--accept-reset]        only take changes from other devices
  sshr sync push                         same as sshr sync
  sshr sync status                       server, devices, state fingerprint
  sshr sync remove-device <id|fingerprint>
                                         take a device out, the vault key changes,
                                         on the primary device
  sshr sync init --backend webdav --url <folder> --user <name> [--name <device>]
                                         keep the account in a WebDAV folder (Nextcloud),
                                         the password from SSHR_WEBDAV_PASSWORD or a prompt
  sshr sync store-key --key-id <id>      a new key of the S3 bucket of this account,
                                         the secret from SSHR_S3_SECRET or a prompt
  sshr sync store-key [--user <name>]    a new password of the WebDAV folder
  sshr sync supabase-sql [--replace]     the SQL that prepares a Supabase project and
                                         a new sshr key, --replace drops the old key
  sshr sync init --backend supabase --url https://<ref>.supabase.co --key <publishable key>
                                         keep the account in a Supabase project,
                                         the sshr key from SSHR_SUPABASE_KEY or a prompt
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
	replaceKey := false
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
		case a == "--replace" && sub == "supabase-sql":
			replaceKey = true
		case strings.HasPrefix(a, "-") && sub != "primary":
			// primary reads its own --yes
			fmt.Fprintln(os.Stderr, syncUsage)
			os.Exit(1)
		default:
			rest = append(rest, a)
		}
	}
	if sf.given && sub != "init" && sub != "join" && sub != "store-key" {
		fatal(fmt.Errorf("--backend and the S3, WebDAV and Supabase flags are for sshr sync init and join, later runs read them from the sync state"))
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
			fatal(fmt.Errorf("sshr sync init needs --server <url> or --backend s3, webdav or supabase"))
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
	case "primary":
		if len(rest) < 1 || len(rest) > 2 || len(rest) == 2 && rest[1] != "--yes" {
			fatal(fmt.Errorf("sshr sync primary <id|fingerprint> [--yes], see sshr sync status"))
		}
		yes := len(rest) == 2
		d, err := c.HandPrimary(rest[0], func(name, fingerprint string) bool {
			fmt.Printf("Make %s the primary device, fingerprint %s\nCompare it with sshr sync status on that device, only the primary device adds and removes devices\n", name, fingerprint)
			return yes || askYes("Hand the primary role on?")
		})
		if err != nil {
			fatal(err)
		}
		fmt.Printf("%s is now the primary device\n", d.Name)
	case "recovery":
		cmdSyncRecovery(c, rest)
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
			role := ""
			if d.ID == st.Primary {
				role = "  (primary, adds and removes devices)"
			}
			fmt.Printf("  %s  %s  %s%s\n", d.ID[:8], syncclient.Fingerprint(d.SignPub), d.Name, role)
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
		if ref, err := c.StoreRef(); err == nil && ref != nil && ref.Kind == "supabase" {
			fmt.Println("This account is in a Supabase project and the removed device still holds the sshr key, it can delete objects and stop the sync\nMake a new key and run its SQL in the project, it drops the old one:\n  sshr sync supabase-sql --replace\nthen run on every device that stays, with the new key:\n  sshr sync store-key")
		} else if err == nil && ref != nil && ref.Kind == "webdav" {
			fmt.Println("This account is in a WebDAV folder and the removed device still knows the password, it can delete files and stop the sync\nChange the password (in Nextcloud make a new app password and delete the old one), then run on every device that stays:\n  sshr sync store-key\nwith --user <name> on each of them if the user changes too")
		} else if err == nil && ref != nil {
			fmt.Println("This account is in a bucket and the removed device still holds the bucket key, it can delete objects and stop the sync\nMake a new key for the bucket, delete the old one, then run on every device that stays:\n  sshr sync store-key --key-id <new key id>")
		}
	case "supabase-sql":
		key := strings.TrimSpace(os.Getenv("SSHR_SUPABASE_KEY"))
		if key != "" && !replaceKey {
			if err := supastore.CheckSSHRKey(key); err != nil {
				fatal(fmt.Errorf("SSHR_SUPABASE_KEY: %v", err))
			}
		}
		if key == "" || replaceKey {
			if key, err = supastore.NewKey(); err != nil {
				fatal(err)
			}
			fmt.Fprintf(os.Stderr, "sshr key of the account, keep it in a password manager, every device needs it for sshr sync init, join and store-key:\n  %s\n", key)
			if replaceKey && os.Getenv("SSHR_SUPABASE_KEY") != "" {
				fmt.Fprintln(os.Stderr, "SSHR_SUPABASE_KEY still holds the old key, change or unset it wherever it is set, sshr takes it before asking")
			}
		}
		fmt.Print(supastore.SetupSQL(key, replaceKey))
		fmt.Fprintln(os.Stderr, "Run the SQL above in the SQL editor of the Supabase project, then sshr sync init --backend supabase --url https://<ref>.supabase.co --key <publishable key>")
		if !replaceKey {
			fmt.Fprintln(os.Stderr, "It sets the key only in a project without one, a project with a key keeps it and the editor warns, change a key with --replace")
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

// askYes asks a yes or no question on the terminal, without one the answer
// is no and the command says to add --yes
func askYes(q string) bool {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintln(os.Stderr, "sshr: there is no terminal to ask in, add --yes")
		return false
	}
	fmt.Print(q + " [y/N]: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes"
}

const recoveryUsage = `Usage: sshr sync recovery create [--passphrase] [--wait <days>]
       sshr sync recovery cancel`

// cmdSyncRecovery makes, replaces and cancels the recovery kit of the
// account on the primary device
func cmdSyncRecovery(c *syncclient.Client, args []string) {
	if len(args) == 0 {
		fatal(fmt.Errorf("%s", recoveryUsage))
	}
	switch args[0] {
	case "create":
		pass, wait := false, syncclient.DefaultRecoveryWait
		for i := 1; i < len(args); i++ {
			switch {
			case args[i] == "--passphrase":
				pass = true
			case args[i] == "--wait" && i+1 < len(args):
				i++
				days, err := strconv.Atoi(args[i])
				if err != nil || days < 1 {
					fatal(fmt.Errorf("--wait takes whole days, at least 1"))
				}
				wait = time.Duration(days) * 24 * time.Hour
			default:
				fatal(fmt.Errorf("%s", recoveryUsage))
			}
		}
		pw := ""
		if pass {
			pw = readNewPassphrase()
		}
		kit, err := c.CreateRecoveryKit(pw, wait)
		if err != nil {
			fatal(err)
		}
		fmt.Println("Write this down or print it and keep it where you keep your passport, it is shown once.")
		fmt.Println("It brings the account back to a new machine when every device is lost: sshr sync recovery restore.")
		fmt.Println("A restore first claims the account, your devices warn about it and the primary device can cancel it,")
		fmt.Println("the new machine gets the account only after the wait. A kit made before is worth nothing now.")
		fmt.Println()
		fmt.Print(kit.Header)
		fmt.Println()
		fmt.Println(kit.Secret)
	case "cancel":
		if err := c.CancelRecovery(); err != nil {
			fatal(err)
		}
		fmt.Println("The recovery kit is cancelled, its device is out of the account and the vault key changed, make a new one with sshr sync recovery create")
	default:
		fatal(fmt.Errorf("%s", recoveryUsage))
	}
}

// readNewPassphrase asks a passphrase twice on the terminal
func readNewPassphrase() string {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fatal(fmt.Errorf("the passphrase is asked on a terminal, there is none"))
	}
	for {
		fmt.Fprint(os.Stderr, "Passphrase of the recovery kit (it is not on the paper, a forgotten one makes the kit useless): ")
		a, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fatal(err)
		}
		fmt.Fprint(os.Stderr, "Again: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fatal(err)
		}
		if len(a) < 8 {
			fmt.Fprintln(os.Stderr, "sshr: at least 8 characters")
			continue
		}
		if string(a) != string(b) {
			fmt.Fprintln(os.Stderr, "sshr: the two do not match")
			continue
		}
		return string(a)
	}
}
