package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"sshr.dev/internal/app"
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

	switch args[0] {
	case "list", "ls":
		cmdList(store)
	case "add":
		cmdAdd(store, args[1:])
	case "rm", "remove":
		cmdRm(store, args[1:])
	case "connect", "ssh":
		cmdConnect(store, args[1:])
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "sshr: unknown command %q\n", args[0])
		printUsage()
		os.Exit(1)
	}
}

func cmdList(store *app.Store) {
	hosts, err := store.List()
	if err != nil {
		fatal(err)
	}
	if len(hosts) == 0 {
		fmt.Println("No hosts. Use `sshr add` to add one.")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tHOST\tUSER\tPORT\tKEY\tID")
	for _, h := range hosts {
		keyCol := "-"
		if h.Key != "" {
			keyCol = filepath.Base(h.Key)
		}
		id := h.ID
		if len(id) > 8 {
			id = id[:8]
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\n", h.Name, h.Host, h.User, h.Port, keyCol, id)
	}
	w.Flush()
}

func cmdAdd(store *app.Store, args []string) {
	var host, name, user, key string
	port := 22
	positional := make([]string, 0)

	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--name=") || strings.HasPrefix(a, "-n=") {
			name = strings.SplitN(a, "=", 2)[1]
		} else if strings.HasPrefix(a, "--user=") || strings.HasPrefix(a, "-u=") {
			user = strings.SplitN(a, "=", 2)[1]
		} else if strings.HasPrefix(a, "--port=") || strings.HasPrefix(a, "-p=") {
			v := strings.SplitN(a, "=", 2)[1]
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				port = n
			}
		} else if strings.HasPrefix(a, "--key=") || strings.HasPrefix(a, "-k=") {
			key = strings.SplitN(a, "=", 2)[1]
		} else if (a == "-n" || a == "--name") && i+1 < len(args) {
			i++
			name = args[i]
		} else if (a == "-u" || a == "--user") && i+1 < len(args) {
			i++
			user = args[i]
		} else if (a == "-p" || a == "--port") && i+1 < len(args) {
			i++
			if n, err := strconv.Atoi(args[i]); err == nil && n > 0 {
				port = n
			}
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
		fmt.Fprintln(os.Stderr, "Usage: sshr add <host> -u <user> [-n <name>] [-p <port>] [-k <key>]")
		os.Exit(1)
	}
	if user == "" {
		fmt.Fprintln(os.Stderr, "sshr add: -u <user> required")
		os.Exit(1)
	}
	if key != "" {
		expanded := expandHome(key)
		if _, err := os.Stat(expanded); err != nil {
			fmt.Fprintf(os.Stderr, "sshr add: key file not found: %s\n", expanded)
			os.Exit(1)
		}
		key = expanded
	} else {
		key = promptAuthMethod()
	}
	h, err := store.Add(name, host, user, key, port)
	if err != nil {
		fatal(err)
	}
	msg := fmt.Sprintf("Added %s (%s@%s:%d)", h.Name, h.User, h.Host, h.Port)
	if h.Key != "" {
		msg += fmt.Sprintf(" key=%s", h.Key)
	}
	fmt.Println(msg)
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
	rest := make([]string, 0, len(args))
	for _, a := range args {
		switch a {
		case "--mosh":
			useMosh = true
		case "--ssh":
			useMosh = false
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: sshr connect [--mosh|--ssh] <name or id>")
		os.Exit(1)
	}
	query := strings.Join(rest, " ")
	h, err := store.Find(query)
	if err != nil {
		findFailed("connect", query, err)
	}
	sshOpts := []string{}
	if h.Key != "" {
		sshOpts = append(sshOpts, "-i", h.Key)
	}
	sshOpts = append(sshOpts, "-p", strconv.Itoa(h.Port))
	dest := h.User + "@" + h.Host

	if useMosh {
		if code, ok := runMosh(h, sshOpts, dest); ok {
			os.Exit(code)
		}
	}

	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		fatal(fmt.Errorf("ssh not found in PATH"))
	}
	fmt.Printf("Connecting to %s (%s:%d)...\n", h.Name, dest, h.Port)
	os.Exit(run(sshBin, append(sshOpts, "--", dest)...))
}

// moshStartup is how long a failing mosh run still counts as "could not
// start" (no mosh-server, UDP blocked) rather than a session that ended.
const moshStartup = 20 * time.Second

// runMosh connects with mosh. ok=false means mosh is unusable here or did not
// start, and the caller should fall back to plain ssh.
func runMosh(h *app.Host, sshOpts []string, dest string) (code int, ok bool) {
	moshBin, err := exec.LookPath("mosh")
	if err != nil {
		fmt.Fprintln(os.Stderr, "sshr: mosh is not installed, using ssh")
		return 0, false
	}
	// mosh splits --ssh on spaces, so a key path with spaces would break it.
	if strings.ContainsAny(h.Key, " \t") {
		fmt.Fprintln(os.Stderr, "sshr: key path has spaces, mosh cannot pass it; using ssh")
		return 0, false
	}
	fmt.Printf("Connecting to %s (%s:%d) with mosh...\n", h.Name, dest, h.Port)
	started := time.Now()
	code = run(moshBin, "--ssh=ssh "+strings.Join(sshOpts, " "), "--", dest)
	if code != 0 && time.Since(started) < moshStartup {
		fmt.Fprintln(os.Stderr, "sshr: mosh did not start, falling back to ssh")
		return 0, false
	}
	return code, true
}

// run starts a terminal program attached to ours and returns its exit code.
func run(bin string, args ...string) int {
	cmd := exec.Command(bin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fatal(err)
	}
	return 0
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `sshr — SSH host manager

Usage:
  sshr                              open GUI
  sshr list                         list saved hosts
  sshr add <host> -u <user> [-n <name>] [-p <port>] [-k <key>]
                                    add a host
  sshr rm <name or id>              remove a host
  sshr connect [--mosh|--ssh] <name or id>
                                    ssh into a host (mosh if enabled
                                    in settings or with --mosh)
  sshr help                         show this help`)
}

func promptAuthMethod() string {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("\nAuthentication method:")
	fmt.Println("  [1] Specify private key path")
	fmt.Println("  [2] Find key automatically (~/.ssh/)")
	fmt.Println("  [3] Password (no key)")
	fmt.Print("\nChoice [1/2/3]: ")

	if !scanner.Scan() {
		return ""
	}
	choice := strings.TrimSpace(scanner.Text())

	switch choice {
	case "1":
		return promptKeyPath(scanner)
	case "2":
		return pickFromSSHKeys(scanner)
	default:
		return ""
	}
}

func promptKeyPath(scanner *bufio.Scanner) string {
	fmt.Print("Key path: ")
	if !scanner.Scan() {
		return ""
	}
	path := strings.TrimSpace(scanner.Text())
	if path == "" {
		return ""
	}
	expanded := expandHome(path)
	if _, err := os.Stat(expanded); err != nil {
		fmt.Fprintf(os.Stderr, "sshr: key file not found: %s\n", expanded)
		os.Exit(1)
	}
	return expanded
}

func pickFromSSHKeys(scanner *bufio.Scanner) string {
	keys := findSSHKeys()
	if len(keys) == 0 {
		fmt.Println("No keys found in ~/.ssh/")
		fmt.Print("Enter path manually? [y/N]: ")
		if scanner.Scan() && strings.ToLower(strings.TrimSpace(scanner.Text())) == "y" {
			return promptKeyPath(scanner)
		}
		return ""
	}

	fmt.Println("\nFound keys:")
	for i, k := range keys {
		fmt.Printf("  [%d] %s\n", i+1, k)
	}
	fmt.Printf("\nChoice [1-%d]: ", len(keys))

	if !scanner.Scan() {
		return ""
	}
	n, err := strconv.Atoi(strings.TrimSpace(scanner.Text()))
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
		info, err := e.Info()
		if err != nil || info.Size() > 16384 || info.Size() == 0 {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(b), "PRIVATE KEY") {
			continue
		}
		keys = append(keys, path)
	}
	return keys
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
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
	default:
		fmt.Fprintf(os.Stderr, "sshr %s: %v\n", cmd, err)
	}
	os.Exit(1)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "sshr: %v\n", err)
	os.Exit(1)
}
