package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"sshr.dev/internal/app"
	"sshr.dev/internal/syncclient"
	"sshr.dev/internal/desktop"
)

func runCLI(args []string) {
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}
	store, err := app.DefaultStore()
	if err != nil {
		fatal(err)
	}
	// --reuse and --no-reuse work with every command that connects
	kept := make([]string, 0, len(args))
	for _, a := range args {
		switch a {
		case "--reuse", "--no-reuse":
			on := a == "--reuse"
			store.Reuse = &on
			// jump hops run as separate sshr processes and read this
			os.Setenv("SSHR_REUSE", strconv.FormatBool(on))
		default:
			kept = append(kept, a)
		}
	}
	args = kept
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}
	hintStore = store

	switch args[0] {
	case "list", "ls":
		cmdList(store, args[1:])
	case "ping":
		cmdPing(store, args[1:])
	case "show":
		cmdShow(store, args[1:])
	case "key":
		cmdKey(store, args[1:])
	case "tag":
		cmdTag(store, args[1:])
	case "gateway":
		cmdGateway(store, args[1:])
	case "run":
		cmdRun(store, args[1:])
	case "send":
		cmdCopy(store, true, args[1:])
	case "get":
		cmdCopy(store, false, args[1:])
	case "add":
		cmdAdd(store, args[1:])
	case "rm", "remove":
		cmdRm(store, args[1:])
	case "connect", "ssh":
		cmdConnect(store, args[1:])
	case "paste":
		cmdPaste(store, args[1:])
	case "forward", "fwd":
		cmdForward(store, args[1:])
	case "tunnel":
		cmdTunnel(store, args[1:])
	case "close":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: sshr close <name or id>")
			os.Exit(1)
		}
		h := findHost(store, "close", strings.Join(args[1:], " "))
		if err := store.CloseMaster(h); err != nil {
			fatal(err)
		}
		fmt.Printf("Closed the shared connection to %s\n", h.Name)
	case "mcp":
		cmdMCP(store, args[1:])
	case "serve":
		cmdServe(store, args[1:])
	case "sync":
		cmdSync(store, args[1:])
	case "import", "import-ssh-config":
		cmdImportSSHConfig(store, args[1:])
	case "desktop-entry":
		cmdDesktopEntry(args[1:])
	case "op-accounts":
		acc, err := app.ListOPAccounts()
		if err != nil {
			fatal(err)
		}
		for _, a := range acc {
			fmt.Printf("%s\t%s\t%s\n", a.Email, a.URL, a.Ref())
		}
	case "export", "export-ssh-config":
		cmdExportSSHConfig(store, args[1:])
	case app.ProxyCommandName:
		cmdProxy(store, args[1:])
	case "completion":
		cmdCompletion(args[1:])
	case completeCommand:
		cmdComplete(store, args[1:])
	case "vault":
		cmdVault(args[1:])
	case "commands":
		cmdCommands(store, args[1:])
	case "ext":
		cmdExt(store, args[1:])
	case "help", "--help", "-h":
		cmdHelp(args[1:])
	default:
		// an installed extension answers to its name, only when no built-in
		// command has it
		runExtension(args[0], args[1:])
		unknownCommand(args[0])
	}
}

func cmdList(store *app.Store, args []string) {
	st, _ := app.LoadSettings()
	ping := st.HealthCheck
	recent, asJSON := false, false
	var query []string
	for _, a := range args {
		switch {
		case a == "--json":
			asJSON = true
		case a == "--recent":
			recent = true
		case a == "--ping":
			ping = true
		case a == "--no-ping":
			ping = false
		case strings.HasPrefix(a, "-"):
			fmt.Fprintln(os.Stderr, "Usage: sshr list [--recent] [--ping|--no-ping] [--json] [search words, tag:x or #x]")
			os.Exit(1)
		default:
			query = append(query, a)
		}
	}
	all, err := store.List()
	if err != nil {
		fatal(err)
	}
	if len(all) == 0 && !asJSON {
		fmt.Println("No hosts. Use `sshr add` to add one.")
		return
	}
	hosts := app.Filter(all, strings.Join(query, " "))
	if len(hosts) == 0 && !asJSON {
		fmt.Printf("No hosts match %q\n", strings.Join(query, " "))
		os.Exit(1)
	}
	var health map[string]app.Health
	if ping {
		health = app.CheckHealthAll(hosts)
	}
	if recent {
		app.SortRecent(hosts)
	}
	if asJSON {
		out := make([]listJSON, 0, len(hosts))
		for _, h := range hosts {
			item := listJSON{HostSummary: h.Summary()}
			if ping {
				hj := toHealthJSON(health[h.ID])
				item.Status = &hj
			}
			out = append(out, item)
		}
		printJSON(out)
		return
	}
	now := time.Now()
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	if ping {
		fmt.Fprint(w, "STATUS\t")
	}
	if recent {
		fmt.Fprint(w, "LAST\t")
	}
	fmt.Fprintln(w, "NAME\tHOST\tUSER\tPORT\tAUTH\tTAGS\tID")
	for _, h := range hosts {
		keyCol := h.AuthShort()
		id := h.ID
		if len(id) > 8 {
			id = id[:8]
		}
		if ping {
			fmt.Fprint(w, health[h.ID].Label()+"\t")
		}
		if recent {
			fmt.Fprint(w, app.Ago(h.LastConnected, now)+"\t")
		}
		tagCol := strings.Join(h.Tags, ",")
		if tagCol == "" {
			tagCol = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n", h.Name, h.Host, h.User, h.Port, keyCol, tagCol, id)
	}
	w.Flush()
}

func cmdAdd(store *app.Store, args []string) {
	var host, name, user, key, jump, gateway, session string
	noKey, askPassword, keyStdin := false, false, false
	// 1Password: --op-password / --op-key link existing items,
	// --store 1password creates an item from the password typed now
	var opPassword, opKey, store1, opVault string
	// Bitwarden: --bw-password / --bw-key link existing items by ID
	var bwPassword, bwKey string
	// --agent system|1password|<socket> keeps the key in an ssh agent,
	// --agent-key picks one of its keys
	var agentName, agentKey string
	useAgent := false
	var tags []string
	port := 22
	positional := make([]string, 0)

	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--name=") || strings.HasPrefix(a, "-n=") {
			name = strings.SplitN(a, "=", 2)[1]
		} else if strings.HasPrefix(a, "--user=") || strings.HasPrefix(a, "-u=") {
			user = strings.SplitN(a, "=", 2)[1]
		} else if strings.HasPrefix(a, "--port=") || strings.HasPrefix(a, "-p=") {
			port = mustPort(strings.SplitN(a, "=", 2)[1])
		} else if strings.HasPrefix(a, "--key=") || strings.HasPrefix(a, "-k=") {
			key = strings.SplitN(a, "=", 2)[1]
		} else if strings.HasPrefix(a, "--jump=") || strings.HasPrefix(a, "-J=") {
			jump = strings.SplitN(a, "=", 2)[1]
		} else if (a == "-J" || a == "--jump") && i+1 < len(args) {
			i++
			jump = args[i]
		} else if strings.HasPrefix(a, "--gateway=") {
			gateway = strings.SplitN(a, "=", 2)[1]
		} else if a == "--gateway" && i+1 < len(args) {
			i++
			gateway = args[i]
		} else if strings.HasPrefix(a, "--session=") {
			session = strings.SplitN(a, "=", 2)[1]
		} else if a == "--session" && i+1 < len(args) {
			i++
			session = args[i]
		} else if strings.HasPrefix(a, "--tag=") {
			tags = append(tags, app.SplitTags(strings.SplitN(a, "=", 2)[1])...)
		} else if (a == "-t" || a == "--tag") && i+1 < len(args) {
			i++
			tags = append(tags, app.SplitTags(args[i])...)
		} else if a == "--no-key" {
			noKey = true
		} else if a == "--ask-password" {
			askPassword = true
		} else if a == "--key-stdin" {
			keyStdin = true
		} else if a == "--agent" && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			i++
			useAgent, agentName = true, args[i]
		} else if a == "--agent" {
			useAgent = true
		} else if a == "--agent-key" && i+1 < len(args) {
			i++
			agentKey = args[i]
		} else if a == "--bw-password" && i+1 < len(args) {
			i++
			bwPassword = args[i]
		} else if a == "--bw-key" && i+1 < len(args) {
			i++
			bwKey = args[i]
		} else if (a == "--op-password" || a == "--op-key" || a == "--store" || a == "--op-vault") && i+1 < len(args) {
			i++
			switch a {
			case "--op-password":
				opPassword = args[i]
			case "--op-key":
				opKey = args[i]
			case "--store":
				store1 = args[i]
			case "--op-vault":
				opVault = args[i]
			}
		} else if (a == "-n" || a == "--name") && i+1 < len(args) {
			i++
			name = args[i]
		} else if (a == "-u" || a == "--user") && i+1 < len(args) {
			i++
			user = args[i]
		} else if (a == "-p" || a == "--port") && i+1 < len(args) {
			i++
			port = mustPort(args[i])
		} else if (a == "-k" || a == "--key") && i+1 < len(args) {
			i++
			key = args[i]
		} else if !strings.HasPrefix(a, "-") {
			positional = append(positional, a)
		}
	}

	if len(positional) > 0 {
		host = positional[0]
	}
	if host == "" {
		fmt.Fprintln(os.Stderr, "Usage: sshr add <host> -u <user> [-n <name>] [-p <port>] [-k <key> | --key-stdin | --agent [name] | --no-key | --ask-password] [-J <jump>] [--session tmux|zellij]")
		os.Exit(1)
	}
	if user == "" {
		fmt.Fprintln(os.Stderr, "sshr add: -u <user> required")
		os.Exit(1)
	}
	if key != "" && noKey {
		fmt.Fprintln(os.Stderr, "sshr add: -k and --no-key cannot be used together")
		os.Exit(1)
	}
	if askPassword && (key != "" || noKey) {
		fmt.Fprintln(os.Stderr, "sshr add: --ask-password cannot be used with -k or --no-key")
		os.Exit(1)
	}
	if keyStdin && (key != "" || noKey || askPassword) {
		fmt.Fprintln(os.Stderr, "sshr add: --key-stdin cannot be used with -k, --no-key or --ask-password")
		os.Exit(1)
	}
	if store1 != "" && store1 != "1password" && store1 != "sshr" {
		fmt.Fprintf(os.Stderr, "sshr add: --store takes sshr or 1password, got %q\n", store1)
		os.Exit(1)
	}
	if n := countTrue(key != "", noKey, askPassword, keyStdin, opPassword != "", opKey != "", bwPassword != "", bwKey != "", useAgent); n > 1 {
		fmt.Fprintln(os.Stderr, "sshr add: choose one of -k, --key-stdin, --no-key, --ask-password, --op-password, --op-key, --bw-password, --bw-key, --agent")
		os.Exit(1)
	}
	if agentKey != "" && !useAgent {
		fmt.Fprintln(os.Stderr, "sshr add: --agent-key needs --agent")
		os.Exit(1)
	}
	if opVault != "" {
		st, _ := app.LoadSettings()
		st.OPVault = opVault
		// only for this run, the setting on disk is left as it is
		store.OPVault = &st.OPVault
	}
	var password, passwordMode, keyMode, keyRef, passwordRef string
	var keyData []byte
	if useAgent {
		keyMode = app.KeyAgent
		if agentKey == "" {
			agentKey = promptAgentKey(agentName)
		}
	} else if opPassword != "" {
		passwordMode, passwordRef = app.PasswordOnePassword, opPassword
	} else if opKey != "" {
		keyMode, keyRef = app.KeyOnePassword, opKey
	} else if bwPassword != "" {
		passwordMode, passwordRef = app.PasswordBitwarden, bwPassword
	} else if bwKey != "" {
		keyMode, keyRef = app.KeyBitwarden, bwKey
	} else if keyStdin {
		mustKeychain()
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
		if err != nil {
			fatal(err)
		}
		keyData = b
	} else if askPassword {
		passwordMode = app.PasswordAsk
	} else if key != "" {
		expanded := app.ExpandHome(key)
		if err := app.CheckPrivateKey(expanded); err != nil {
			fmt.Fprintf(os.Stderr, "sshr add: %v\n", err)
			os.Exit(1)
		}
		key = expanded
	} else if !noKey {
		key, password, passwordMode, keyData = promptAuthMethod()
	} else if store1 == "1password" {
		password, passwordMode = promptPasswordPlain(bufio.NewScanner(os.Stdin)), app.PasswordOnePassword
	} else {
		password, passwordMode = promptPassword(), app.PasswordSaved
	}
	in := app.Host{
		Name: name, Host: host, User: user, Port: port,
		Key: key, KeyData: keyData, KeyMode: keyMode, KeyRef: keyRef,
		Agent: agentName, AgentKey: agentKey,
		PasswordMode: passwordMode, Password: password, PasswordRef: passwordRef,
		Jump: jump, Gateway: gateway, Session: session, Tags: tags,
	}
	h, err := store.Add(in)
	if errors.Is(err, app.ErrKeyPassphrase) {
		// the key may have come on stdin, the passphrase is read from the
		// terminal, it opens the key once and is not stored
		if in.KeyPassphrase, err = app.AskTerminal("Key passphrase: "); err != nil {
			fatal(fmt.Errorf("the key has a passphrase and there is no terminal to ask for it"))
		}
		h, err = store.Add(in)
	}
	if err != nil {
		fatal(err)
	}
	msg := fmt.Sprintf("Added %s (%s@%s:%d)", h.Name, h.User, h.Host, h.Port)
	msg += " auth=" + h.AuthShort()
	if fp := h.KeyFingerprint(); fp != "" {
		msg += " (" + fp + ")"
	} else if h.PasswordRef != "" {
		msg += " (" + h.PasswordRef + ")"
	}
	if h.Jump != "" {
		msg += " via " + h.Jump
	}
	if h.Gateway != "" {
		msg += " gateway=" + h.Gateway
	}
	if h.Session != "" {
		msg += " session=" + h.Session
	}
	fmt.Println(msg)
}

// mustPort parses -p for add and exits on anything outside 1–65535.
func mustPort(v string) int {
	n, err := app.ParsePort(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshr add: invalid port %q (expected 1-65535)\n", v)
		os.Exit(1)
	}
	return n
}

func cmdRm(store *app.Store, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: sshr rm <name or id>")
		os.Exit(1)
	}
	query := strings.Join(args, " ")
	h, err := store.Find(query)
	if err != nil {
		findFailed("rm", query, err)
	}
	if err := store.Delete(h.ID); err != nil {
		fatal(err)
	}
	fmt.Printf("Removed %s (%s@%s:%d)\n", h.Name, h.User, h.Host, h.Port)
}

func cmdConnect(store *app.Store, args []string) {
	settings, _ := app.LoadSettings()
	useMosh := settings.Mosh
	plain := false
	var fwdNames []string
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "-F", "--forward":
			if i+1 < len(args) {
				i++
				fwdNames = append(fwdNames, args[i])
			}
		case "--mosh":
			useMosh = true
		case "--ssh":
			useMosh = false
		case "--plain":
			plain = true
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: sshr connect [--mosh|--ssh] [--plain] [-F <forward>|all] <name or id>")
		os.Exit(1)
	}
	query := strings.Join(rest, " ")
	h, err := store.Find(query)
	unsaved := false
	if errors.Is(err, app.ErrNotFound) && strings.Contains(query, "@") {
		// user@host[:port] or ssh://... that is not saved, connect once
		tmp, perr := app.ParseDestination(query)
		if perr != nil {
			fatal(perr)
		}
		h, err, unsaved = &tmp, nil, true
	}
	if err != nil {
		findFailed("connect", query, err)
	}
	if unsaved {
		fmt.Fprintf(os.Stderr, "sshr: %s is not saved, connecting once\n", query)
	}
	var fwds []app.Forward
	if len(fwdNames) > 0 {
		if fwds, err = app.FindForwards(h.Forwards, fwdNames); err != nil {
			fatal(err)
		}
	}
	plan, err := store.PlanSession(h, app.LaunchOptions{Forwards: fwds, Mosh: useMosh, Plain: plain})
	if err != nil {
		fatal(err)
	}
	for _, note := range plan.Notes {
		fmt.Fprintln(os.Stderr, "sshr: "+note)
	}
	dest := h.Dest()
	if plan.Tool == "mosh" {
		if _, err := plan.ToolPath(); err != nil {
			fatal(err)
		}
		fmt.Printf("Connecting to %s (%s:%d) with mosh...\n", h.Name, dest, h.Port)
		// the secrets are fetched after the line, a password manager prompt
		// belongs to this connect
		cmd, cleanup, err := plan.Command()
		if err != nil {
			fatal(err)
		}
		started := time.Now()
		code := runAttached(cmd, cleanup)
		if !app.MoshStartFailed(code, time.Since(started)) {
			markConnected(store, h, code)
			os.Exit(code)
		}
		fmt.Fprintln(os.Stderr, "sshr: mosh did not start, falling back to ssh")
		plan = plan.Fallback
	}

	if _, err := plan.ToolPath(); err != nil {
		fatal(err)
	}
	via := ""
	if plan.Via != "" {
		via = " via " + plan.Via
	}
	if h.Jump == "" && plan.Via != "" {
		via += " (no answer directly)"
	}
	if plan.Session != "" {
		via += ", " + plan.Session + " session " + app.SessionName
	}
	fmt.Printf("Connecting to %s (%s:%d)%s...\n", h.Name, dest, h.Port, via)
	cmd, cleanup, err := plan.Command()
	if err != nil {
		fatal(err)
	}
	code := runAttached(cmd, cleanup)
	markConnected(store, h, code)
	os.Exit(code)
}

// markConnected notes the session for sshr list --recent, 255 is ssh
// failing to connect at all, any other code is a session that was open
func markConnected(store *app.Store, h *app.Host, code int) {
	if h.ID == "" {
		// a destination that is not saved, offer to keep it
		if code != 255 {
			offerSave(store, h)
		}
		return
	}
	if code != 255 {
		store.MarkConnected(h.ID)
	}
}

// offerSave asks on a terminal whether to keep a destination connected to
// once, nothing is asked without one, it logs in as ssh did, with the
// default keys, the agent or a password prompt
func offerSave(store *app.Store, h *app.Host) {
	if h.ID != "" || !term.IsTerminal(int(os.Stdin.Fd())) {
		return
	}
	fmt.Printf("Save %s@%s as a host? Type a name, or Enter to skip: ", h.User, h.Host)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	name := strings.TrimSpace(line)
	if name == "" {
		return
	}
	h.Name = name
	saved, err := store.Add(*h)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshr: not saved: %v\n", err)
		return
	}
	h.ID = saved.ID
	store.MarkConnected(saved.ID)
	fmt.Printf("Saved as %s, sshr connect %s next time\n", saved.Name, saved.Name)
}

// cmdProxy is run by ssh as ProxyCommand ("sshr __proxy <chain> %h %p"), it
// connects to the last hop of the chain with that hop's own key or password
// and forwards stdin/stdout to host:port with ssh -W
func cmdProxy(store *app.Store, args []string) {
	if len(args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: sshr __proxy <jump chain> <host> <port>")
		os.Exit(2)
	}
	hop, sshArgs, err := store.ProxyHop(args[0], args[1], args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshr: %v\n", err)
		os.Exit(1)
	}
	cmd := exec.Command("ssh", sshArgs...)
	// The askpass of the host behind this hop is in our environment, it must
	// not answer this hop's password prompt
	cmd.Env = app.StripAuthEnv(os.Environ())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cleanup, err := app.AttachAuth(cmd, hop)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshr: %v\n", err)
		os.Exit(1)
	}
	err = cmd.Run()
	cleanup()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		fatal(err)
	}
}

// run starts a terminal program attached to ours and returns its exit code.
func run(h *app.Host, bin string, args ...string) int {
	cmd := exec.Command(bin, args...)
	cleanup, err := app.AttachAuth(cmd, h)
	if err != nil {
		fatal(err)
	}
	return runAttached(cmd, cleanup)
}

// runAttached runs cmd on our terminal and returns its exit code, cleanup
// runs after it ends
func runAttached(cmd *exec.Cmd, cleanup func()) int {
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	defer cleanup()
	if err := cmd.Start(); err != nil {
		fatal(err)
	}
	// a signal sent to sshr alone (kill, systemd stop) would end sshr and
	// leave ssh running, a tunnel would keep its port, it goes to the child
	// and sshr waits for it, Ctrl+C reaches both through the process group
	stop := forwardSignals(cmd.Process)
	err := cmd.Wait()
	stop()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fatal(err)
	}
	return 0
}

func promptAuthMethod() (key, password, mode string, keyData []byte) {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("\nAuthentication method:")
	fmt.Println("  [1] Specify private key path")
	fmt.Println("  [2] Find key automatically (~/.ssh/)")
	fmt.Println("  [3] Password, saved encrypted")
	fmt.Println("  [4] Password, asked on every connect")
	fmt.Println("  [5] Paste a private key, stored encrypted in sshr")
	fmt.Print("\nChoice [1/2/3/4/5]: ")

	choice := readAnswer(scanner)
	switch choice {
	case "1":
		return promptKeyPath(scanner), "", "", nil
	case "2":
		return pickFromSSHKeys(scanner), "", "", nil
	case "3":
		return "", promptPasswordWith(scanner), app.PasswordSaved, nil
	case "4":
		return "", "", app.PasswordAsk, nil
	case "5":
		return "", "", "", promptKeyPaste(scanner)
	default:
		fmt.Fprintf(os.Stderr, "\nsshr add: invalid choice %q\n", choice)
		os.Exit(1)
		return "", "", "", nil
	}
}

// promptKeyPaste reads a pasted private key up to its END line
func promptKeyPaste(scanner *bufio.Scanner) []byte {
	mustKeychain()
	fmt.Println("Paste the private key, it ends with the -----END ... line:")
	var b strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		b.WriteString(line + "\n")
		if strings.HasPrefix(strings.TrimSpace(line), "-----END ") {
			return []byte(b.String())
		}
		if b.Len() > 64<<10 {
			break
		}
	}
	fmt.Fprintln(os.Stderr, "sshr add: no -----END line, the key is incomplete")
	os.Exit(1)
	return nil
}

func agentLabel(name string) string {
	if name == "" {
		return "system"
	}
	return name
}

// promptAgentKey lets the user pick one key when the agent has several and
// there is a terminal, with no choice ssh is offered every key
func promptAgentKey(name string) string {
	keys, err := app.AgentKeys(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshr add: %v, saving without a key choice\n", err)
		return ""
	}
	if len(keys) < 2 || !term.IsTerminal(int(os.Stdin.Fd())) {
		return ""
	}
	fmt.Println("\nThe agent has several keys, servers stop after about six tries:")
	for i, k := range keys {
		fmt.Printf("  [%d] %s %s\n", i+1, ssh.FingerprintSHA256(k), k.Comment)
	}
	fmt.Printf("  [0] offer all of them\n\nChoice: ")
	n, err := strconv.Atoi(readAnswer(bufio.NewScanner(os.Stdin)))
	if err != nil || n < 0 || n > len(keys) {
		fmt.Fprintln(os.Stderr, "sshr add: invalid choice")
		os.Exit(1)
	}
	if n == 0 {
		return ""
	}
	return ssh.FingerprintSHA256(keys[n-1])
}

func countTrue(bs ...bool) int {
	n := 0
	for _, b := range bs {
		if b {
			n++
		}
	}
	return n
}

// mustKeychain stops before a secret is typed when it could not be saved
func mustKeychain() {
	if err := app.CheckKeychain(); err != nil {
		fmt.Fprintf(os.Stderr, "sshr add: %v\n", err)
		os.Exit(1)
	}
}

func promptPassword() string {
	return promptPasswordWith(bufio.NewScanner(os.Stdin))
}

// promptPasswordWith checks the keychain first, a password typed only to be
// refused at save is wasted, then reads it
func promptPasswordWith(scanner *bufio.Scanner) string {
	if err := app.CheckKeychain(); err != nil {
		fmt.Fprintf(os.Stderr, "sshr add: %v (--ask-password)\n", err)
		os.Exit(1)
	}
	return promptPasswordPlain(scanner)
}

// promptPasswordPlain reads a password hidden from a terminal, or as a line
// from a pipe
func promptPasswordPlain(scanner *bufio.Scanner) string {
	fmt.Print("Password: ")
	var pw string
	if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Println()
		if err != nil {
			fatal(err)
		}
		pw = string(b)
	} else {
		if !scanner.Scan() {
			fmt.Fprintln(os.Stderr, "\nsshr add: no answer on stdin")
			os.Exit(1)
		}
		pw = scanner.Text()
	}
	if pw == "" {
		fmt.Fprintln(os.Stderr, "sshr add: empty password")
		os.Exit(1)
	}
	return pw
}

// readAnswer reads one line of a prompt. With no input to read (stdin
// closed, as in scripts and CI) it exits instead of guessing: saving a host
// without the key the user meant would only fail later, on connect.
func readAnswer(scanner *bufio.Scanner) string {
	if !scanner.Scan() {
		fmt.Fprintln(os.Stderr, "\nsshr add: no answer on stdin; pass -k <key> or --no-key")
		os.Exit(1)
	}
	return strings.TrimSpace(scanner.Text())
}

func promptKeyPath(scanner *bufio.Scanner) string {
	fmt.Print("Key path: ")
	path := readAnswer(scanner)
	if path == "" {
		fmt.Fprintln(os.Stderr, "sshr add: empty key path")
		os.Exit(1)
	}
	expanded := app.ExpandHome(path)
	if err := app.CheckPrivateKey(expanded); err != nil {
		fmt.Fprintf(os.Stderr, "sshr add: %v\n", err)
		os.Exit(1)
	}
	return expanded
}

func pickFromSSHKeys(scanner *bufio.Scanner) string {
	keys := findSSHKeys()
	if len(keys) == 0 {
		fmt.Println("No keys found in ~/.ssh/")
		fmt.Print("Enter path manually? [y/N]: ")
		if strings.ToLower(readAnswer(scanner)) == "y" {
			return promptKeyPath(scanner)
		}
		fmt.Fprintln(os.Stderr, "sshr add: no key chosen; use --no-key for password login")
		os.Exit(1)
	}

	fmt.Println("\nFound keys:")
	for i, k := range keys {
		fmt.Printf("  [%d] %s\n", i+1, k)
	}
	fmt.Printf("\nChoice [1-%d]: ", len(keys))

	n, err := strconv.Atoi(readAnswer(scanner))
	if err != nil || n < 1 || n > len(keys) {
		fmt.Fprintln(os.Stderr, "sshr: invalid choice")
		os.Exit(1)
	}
	return keys[n-1]
}

func findSSHKeys() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	sshDir := filepath.Join(home, ".ssh")
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil
	}
	var keys []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".pub") || name == "known_hosts" ||
			name == "known_hosts.old" || name == "authorized_keys" || name == "config" {
			continue
		}
		path := filepath.Join(sshDir, name)
		if app.CheckPrivateKey(path) != nil {
			continue
		}
		keys = append(keys, path)
	}
	return keys
}

// findFailed reports a failed Find and exits; on ambiguity it lists the
// matches so the user can retry with an ID.
func findFailed(cmd, query string, err error) {
	var amb *app.AmbiguousError
	switch {
	case errors.As(err, &amb):
		fmt.Fprintf(os.Stderr, "sshr %s: %q matches several hosts, use the ID:\n", cmd, query)
		for _, h := range amb.Hosts {
			fmt.Fprintf(os.Stderr, "  %s  %s (%s@%s:%d)\n", h.ID, h.Name, h.User, h.Host, h.Port)
		}
	case errors.Is(err, app.ErrNotFound):
		fmt.Fprintf(os.Stderr, "sshr %s: %s not found\n", cmd, query)
		if near := hostHint(query); len(near) > 0 {
			fmt.Fprintf(os.Stderr, "did you mean: %s\n", strings.Join(near, ", "))
		} else {
			fmt.Fprintln(os.Stderr, "sshr list shows the saved hosts")
		}
	default:
		fmt.Fprintf(os.Stderr, "sshr %s: %v\n", cmd, err)
	}
	os.Exit(1)
}

func fatal(err error) {
	if errors.Is(err, app.ErrChanged) {
		err = errors.New("the host was saved meanwhile (a sync or the app), nothing is changed, run the command again")
	}
	fmt.Fprintf(os.Stderr, "sshr: %v\n", err)
	os.Exit(1)
}

// cmdImportSSHConfig adds the hosts of ~/.ssh/config
func cmdImportSSHConfig(store *app.Store, args []string) {
	dry := false
	for _, a := range args {
		if a != "--dry-run" {
			fmt.Fprintln(os.Stderr, "Usage: sshr import [--dry-run]")
			os.Exit(1)
		}
		dry = true
	}
	items, err := store.ImportSSHConfig(dry)
	if err != nil {
		fatal(err)
	}
	added := 0
	for _, it := range items {
		switch {
		case it.Host != nil:
			added++
			h := it.Host
			line := fmt.Sprintf("+ %s  %s@%s:%d", h.Name, h.User, h.Host, h.Port)
			switch {
			case h.Key != "":
				line += "  key " + h.Key
			case h.KeyMode == app.KeyAgent:
				line += "  agent " + agentLabel(h.Agent)
			}
			if h.Jump != "" {
				line += "  via " + h.Jump
			}
			if len(h.Forwards) > 0 {
				line += fmt.Sprintf("  %d forwards", len(h.Forwards))
			}
			fmt.Println(line)
		default:
			fmt.Printf("- %s  %s\n", it.Alias, it.Skipped)
		}
		for _, n := range it.Notes {
			fmt.Printf("    %s\n", n)
		}
	}
	if dry {
		fmt.Printf("%d hosts would be added, nothing was saved (--dry-run)\n", added)
	} else {
		fmt.Printf("Added %d hosts\n", added)
	}
}

// cmdExportSSHConfig prints the hosts as ssh config or installs the export
func cmdExportSSHConfig(store *app.Store, args []string) {
	usage := func() {
		fmt.Fprintln(os.Stderr, "Usage: sshr export [--install|--uninstall]")
		os.Exit(1)
	}
	if len(args) > 1 {
		usage()
	}
	mode := ""
	if len(args) == 1 {
		mode = args[0]
	}
	var items []app.ExportItem
	var err error
	switch mode {
	case "":
		items, err = store.WriteSSHConfig(os.Stdout)
	case "--install":
		items, err = store.InstallSSHConfig()
	case "--uninstall":
		if err := store.UninstallSSHConfig(); err != nil {
			fatal(err)
		}
		fmt.Println("Removed the export and its Include line")
		return
	default:
		usage()
	}
	for _, it := range items {
		switch {
		case it.Skipped != "":
			fmt.Fprintf(os.Stderr, "- %s  %s\n", it.Name, it.Skipped)
		case it.Note != "":
			fmt.Fprintf(os.Stderr, "  %s  %s\n", it.Alias, it.Note)
		}
	}
	if errors.Is(err, app.ErrSSHConfigLink) {
		// the export is written, only the Include line is left to the user
		fmt.Fprintf(os.Stderr, "sshr: %v\n", strings.TrimPrefix(err.Error(), app.ErrSSHConfigLink.Error()+": "))
		os.Exit(1)
	}
	if err != nil {
		fatal(err)
	}
	if mode == "--install" {
		fmt.Printf("Wrote %s, ssh reads it from ~/.ssh/config, it is kept up to date\n", store.SSHConfigOut)
	}
}

// cmdPing checks the given hosts, all when none is given
func cmdPing(store *app.Store, args []string) {
	asJSON, keys := false, false
	kept := args[:0:0]
	for _, a := range args {
		switch a {
		case "--json":
			asJSON = true
			continue
		case "--keys":
			keys = true
			continue
		}
		kept = append(kept, a)
	}
	args = kept
	var hosts []app.Host
	if len(args) == 0 {
		var err error
		if hosts, err = store.List(); err != nil {
			fatal(err)
		}
	}
	for _, a := range args {
		hosts = append(hosts, *findHost(store, "ping", a))
	}
	res := app.CheckHealthAll(hosts)
	var hk map[string]app.HostKey
	if keys {
		hk = app.CheckHostKeyAll(hosts)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	code := 0
	out := make([]pingJSON, 0, len(hosts))
	for _, h := range hosts {
		r := res[h.ID]
		if r.State == app.HealthDown || r.State == app.HealthNotSSH {
			code = 1
		}
		k := hk[h.ID]
		if k.State == app.KeyChanged {
			code = 1
		}
		if asJSON {
			p := pingJSON{Name: h.Name, ID: h.ID, healthJSON: toHealthJSON(r)}
			if keys {
				p.KeyType, p.KeyFingerprint, p.KeyState = k.Type, k.Fingerprint, k.State
			}
			out = append(out, p)
			continue
		}
		if keys {
			key := k.Err
			if k.Fingerprint != "" {
				key = k.Type + " " + k.Fingerprint + " (" + k.State + ")"
				if k.State == app.KeyChanged {
					key += " THE SERVER KEY CHANGED, check before connecting"
				}
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", h.Name, r.Label(), gatewayReason(h, r), key)
			continue
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", h.Name, r.Label(), gatewayReason(h, r))
	}
	if asJSON {
		printJSON(out)
	}
	w.Flush()
	os.Exit(code)
}

// gatewayReason is the reason of a ping result, a host down directly that
// has a gateway says connect goes through it
func gatewayReason(h app.Host, r app.Health) string {
	if r.State != app.HealthDown || h.Gateway == "" {
		return r.Reason
	}
	return r.Reason + ", connect goes through " + h.Gateway
}

// cmdDesktopEntry adds sshr to the application menu or removes it
func cmdDesktopEntry(args []string) {
	switch {
	case len(args) == 1 && args[0] == "--remove":
		if err := desktop.Remove(); err != nil {
			fatal(err)
		}
		fmt.Println("Removed sshr from the application menu")
	case len(args) == 0:
		if !guiBuilt {
			fatal(errors.New("this build has no GUI, there is nothing to open from the menu"))
		}
		path, err := desktop.Install()
		if err != nil {
			fatal(err)
		}
		fmt.Printf("Added sshr to the application menu: %s\n", path)
	default:
		fmt.Fprintln(os.Stderr, "Usage: sshr desktop-entry [--remove]")
		os.Exit(1)
	}
}

// cmdTag shows a host's tags or changes them: +x or x adds, -x removes
// cmdVault shows where the vault key lives and moves it between the system
// keychain and a file under a passphrase
func cmdVault(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: sshr vault status|passphrase|keychain")
		os.Exit(1)
	}
	// the keys of the sync device move with the vault key
	var names []string
	if args[0] == "passphrase" || args[0] == "keychain" {
		dir, err := syncclient.DefaultDir()
		if err != nil {
			fatal(err)
		}
		if names, err = syncclient.SecretNames(dir); err != nil {
			fatal(fmt.Errorf("%v, nothing is changed", err))
		}
	}
	switch args[0] {
	case "status":
		fmt.Println(app.VaultMode())
	case "passphrase":
		first, err := app.AskTerminal("New vault passphrase: ")
		if err != nil {
			fatal(fmt.Errorf("the passphrase is asked on a terminal: %v", err))
		}
		again, err := app.AskTerminal("Again: ")
		if err != nil {
			fatal(err)
		}
		if first != again {
			fatal(fmt.Errorf("the two passphrases differ, nothing is changed"))
		}
		if err := app.SetVaultPassphrase(first, names); err != nil {
			fatal(err)
		}
		fmt.Println("The vault key and the sync keys are now in ~/.sshr/vault under the passphrase, a forgotten passphrase loses the saved passwords and keys")
	case "keychain":
		if err := app.UseKeychainVault(names); err != nil {
			fatal(err)
		}
		fmt.Println("The vault key and the sync keys are in the system keychain again, the passphrase files are removed")
	default:
		fmt.Fprintln(os.Stderr, "Usage: sshr vault status|passphrase|keychain")
		os.Exit(1)
	}
}

const commandsUsage = "Usage: sshr commands list|only|all|allow <host>|deny <host>"

// cmdCommands keeps the list of hosts assistants and scripts may run
// commands on through sshr mcp and sshr serve
func cmdCommands(store *app.Store, args []string) {
	if len(args) == 0 || len(args) > 2 {
		fmt.Fprintln(os.Stderr, commandsUsage)
		os.Exit(1)
	}
	st, err := app.LoadSettings()
	if err != nil {
		fatal(err)
	}
	switch {
	case args[0] == "list" && len(args) == 1:
		if !st.CommandsListedOnly {
			fmt.Println("every host takes commands when they are on, sshr commands only limits them to the hosts below")
		} else {
			fmt.Println("only the hosts below take commands")
		}
		hosts, err := store.List()
		if err != nil {
			fatal(err)
		}
		for i := range hosts {
			if _, ok := st.CommandHosts[hosts[i].ID]; !ok {
				continue
			}
			state := "allowed"
			if st.CommandHosts[hosts[i].ID] != store.CommandTarget(&hosts[i]) {
				state = "points elsewhere since it was allowed, allow it again"
			}
			fmt.Printf("  %s (%s): %s\n", hosts[i].Name, hosts[i].Dest(), state)
		}
		return
	case args[0] == "only" && len(args) == 1:
		st.CommandsListedOnly = true
	case args[0] == "all" && len(args) == 1:
		st.CommandsListedOnly = false
	case args[0] == "allow" && len(args) == 2:
		h := findHost(store, "commands allow", args[1])
		st.AllowCommands(h.ID, store.CommandTarget(h))
	case args[0] == "deny" && len(args) == 2:
		st.DenyCommands(findHost(store, "commands deny", args[1]).ID)
	default:
		fmt.Fprintln(os.Stderr, commandsUsage)
		os.Exit(1)
	}
	if err := app.SaveSettings(st); err != nil {
		fatal(err)
	}
}

// commandPolicy checks a host before a command from sshr mcp or sshr
// serve, it reads the settings each time so sshr commands allow works
// without a restart, a settings file that does not read refuses
func commandPolicy(store *app.Store, listedOnly *bool) func(*app.Host) error {
	return func(h *app.Host) error {
		st, err := app.LoadSettings()
		if err != nil {
			return fmt.Errorf("settings.json does not read, commands are refused: %v", err)
		}
		if listedOnly != nil {
			st.CommandsListedOnly = *listedOnly
		}
		return st.CommandsAllowed(h.ID, h.Name, store.CommandTarget(h))
	}
}

// cmdGateway shows, sets or removes the host connect falls back to when
// a host does not answer directly
func cmdGateway(store *app.Store, args []string) {
	if len(args) < 1 || len(args) > 2 {
		fmt.Fprintln(os.Stderr, "Usage: sshr gateway <name or id> [<gateway>|--off]")
		os.Exit(1)
	}
	h := findHost(store, "gateway", args[0])
	if len(args) == 1 {
		if h.Gateway == "" {
			fmt.Printf("%s: no gateway, connects directly\n", h.Name)
			return
		}
		fmt.Printf("%s: through %s when it does not answer directly\n", h.Name, h.Gateway)
		return
	}
	gateway := args[1]
	if gateway == "--off" {
		gateway = ""
	}
	saved, err := store.SetGateway(h.ID, gateway)
	if err != nil {
		fatal(err)
	}
	if saved.Gateway == "" {
		fmt.Printf("%s: no gateway, connects directly\n", saved.Name)
		return
	}
	fmt.Printf("%s: through %s when it does not answer directly\n", saved.Name, saved.Gateway)
}

func cmdTag(store *app.Store, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: sshr tag <name or id> [+tag|-tag|tag...]")
		os.Exit(1)
	}
	h := findHost(store, "tag", args[0])
	if len(args) == 1 {
		fmt.Println(strings.Join(h.Tags, " "))
		return
	}
	tags := append([]string(nil), h.Tags...)
	for _, a := range args[1:] {
		if t, ok := strings.CutPrefix(a, "-"); ok {
			t = strings.ToLower(strings.TrimPrefix(t, "#"))
			kept := tags[:0]
			for _, x := range tags {
				if x != t {
					kept = append(kept, x)
				}
			}
			tags = kept
			continue
		}
		tags = append(tags, app.SplitTags(strings.TrimPrefix(a, "+"))...)
	}
	in := *h
	in.Tags = tags
	saved, err := store.Update(h.ID, in)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("%s: %s\n", saved.Name, strings.Join(saved.Tags, " "))
}
