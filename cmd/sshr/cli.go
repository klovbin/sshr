package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"

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
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\n", h.Name, h.Host, h.User, h.Port, keyCol, h.ID[:8])
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
		fmt.Fprintf(os.Stderr, "sshr rm: %s not found\n", query)
		os.Exit(1)
	}
	if err := store.Delete(h.ID); err != nil {
		fatal(err)
	}
	fmt.Printf("Removed %s (%s@%s:%d)\n", h.Name, h.User, h.Host, h.Port)
}

func cmdConnect(store *app.Store, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: sshr connect <name or id>")
		os.Exit(1)
	}
	query := strings.Join(args, " ")
	h, err := store.Find(query)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshr connect: %s not found\n", query)
		os.Exit(1)
	}
	sshArgs := []string{"ssh"}
	if h.Key != "" {
		sshArgs = append(sshArgs, "-i", h.Key)
	}
	sshArgs = append(sshArgs, "-p", strconv.Itoa(h.Port), h.User+"@"+h.Host)
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		fatal(fmt.Errorf("ssh not found in PATH"))
	}
	fmt.Printf("Connecting to %s (%s@%s:%d)...\n", h.Name, h.User, h.Host, h.Port)
	syscall.Exec(sshBin, sshArgs, os.Environ())
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `sshr — SSH host manager

Usage:
  sshr                              open GUI
  sshr list                         list saved hosts
  sshr add <host> -u <user> [-n <name>] [-p <port>] [-k <key>]
                                    add a host
  sshr rm <name or id>              remove a host
  sshr connect <name or id>         ssh into a host
  sshr help                         show this help`)
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "sshr: %v\n", err)
	os.Exit(1)
}
