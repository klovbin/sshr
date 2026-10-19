package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"sshr.dev/internal/app"
)

// command is one entry of sshr help, the short line goes to the overview,
// the usage and details to sshr help <name>
type command struct {
	name    string
	aliases []string
	usage   string
	short   string
	details string
}

var commands = []command{
	{name: "list", aliases: []string{"ls"}, usage: "sshr list [--ping|--no-ping] [search...]", short: "list saved hosts",
		details: `words filter by name, address, user and tags, tag:x or #x needs the
exact tag, --ping adds whether each answers (on by default with
health_check)`},
	{name: "add", usage: `sshr add <host> -u <user> [-n <name>] [-p <port>]
         [-k <key> | --key-stdin | --agent [name] | --no-key | --ask-password]
         [-J <jump>] [--session tmux|zellij] [-t <tags>]`, short: "add a host",
		details: `asks for the auth method unless -k, --no-key or --ask-password is
given, --no-key saves a password encrypted with a key from the system
keychain, --ask-password saves none, ssh asks on every connect,
--key-stdin stores the private key read from stdin inside sshr,
encrypted the same way,
--op-password op://v/item/password and --op-key "op://v/item/private key"
read them from 1Password on every connect, --no-key --store 1password
creates a 1Password item from the password (--op-vault <name>),
--bw-password <item id> and --bw-key <item id> read them from Bitwarden
(bw, with BW_SESSION set),
--agent [system|1password|<socket>] uses a key from an ssh agent,
--agent-key <fingerprint|comment> picks one of its keys,
-J a,b goes through jump hosts: saved host names or [user@]host[:port],
--session attaches to tmux/zellij on connect (off by default)`},
	{name: "rm", aliases: []string{"remove"}, usage: "sshr rm <name or id>", short: "remove a host"},
	{name: "connect", aliases: []string{"ssh"}, usage: "sshr connect [--mosh|--ssh] [--plain] [-F <forward>|all] <name or id>", short: "ssh into a host",
		details: `mosh if enabled in settings or with --mosh, --plain skips the host's
session, -F also opens saved forwards`},
	{name: "ping", usage: "sshr ping [name or id...]", short: "check whether hosts answer",
		details: `TCP connect time and the SSH banner, no login, exits 1 when one is
down`},
	{name: "tag", usage: "sshr tag <name or id> [+tag|-tag|tag...]", short: "show, add or remove tags",
		details: `+tag or a bare tag adds it, -tag removes it, no tags shows them`},
	{name: "run", usage: "sshr run [-t <tag>]... [-j N] [--timeout S] [name...] -- <command>", short: "run a command on many hosts",
		details: `by name and by tag (all tags), 8 at a time, each host's output as a
block, exits 1 when one fails`},
	{name: "send", usage: "sshr send <name or id> <path>... [--to <remote folder>] [--legacy]", short: "copy files to a host",
		details: `scp with the host's own key, password and jump hosts, folders too,
the home folder by default, --legacy uses the old scp protocol for
servers without SFTP`},
	{name: "get", usage: "sshr get <name or id> <remote path>... [--to <local folder>] [--legacy]", short: "copy files from a host",
		details: `as send, into the current folder by default`},
	{name: "forward", aliases: []string{"fwd"}, usage: `sshr forward <host>
sshr forward add <host> <name> -L|-R|-D <spec>
sshr forward rm <host> <name>`, short: "list, save or remove port forwards",
		details: `a spec as for ssh, e.g. db -L 5432:localhost:5432`},
	{name: "tunnel", usage: "sshr tunnel <host> [names...]", short: "open forwards without a shell",
		details: `all saved forwards when no names are given, Ctrl+C closes them`},
	{name: "close", usage: "sshr close <name or id>", short: "close the shared connection to a host"},
	{name: "paste", usage: "sshr paste [-c] [-f <file>] <name or id>", short: "upload the clipboard image",
		details: `uploads the clipboard image (or a file) to the host and prints its
path there, -c also copies that path, removed from the server after 15
minutes`},
	{name: "mcp", usage: "sshr mcp [--allow-commands|--no-commands]", short: "MCP server for AI assistants",
		details: `on stdin and stdout: list hosts, upload files, run commands only with
--allow-commands or the mcp_commands setting (off by default)`},
	{name: "serve", usage: "sshr serve [--listen unix:<path>|127.0.0.1:<port>] [--allow-commands]", short: "local REST API",
		details: `a unix socket by default, a loopback port needs the token from
~/.sshr/api-token, no secrets are returned, commands are off by default`},
	{name: "sync", usage: "sshr sync [init|invite|join|pending|approve|pull|push|status|remove-device|leave]", short: "sync hosts between devices",
		details: `through an sshr-sync server, end to end encrypted, see sshr sync help`},
	{name: "import", aliases: []string{"import-ssh-config"}, usage: "sshr import [--dry-run]", short: "add the hosts of ~/.ssh/config",
		details: `with keys, agent, jump hosts and forwards, saved hosts are skipped`},
	{name: "export", aliases: []string{"export-ssh-config"}, usage: "sshr export [--install|--uninstall]", short: "write the hosts as ssh config",
		details: `prints the hosts as ssh config, --install writes ~/.sshr/ssh_config,
includes it from ~/.ssh/config and keeps it up to date, so ssh, scp and
editors reach the hosts by name, passwords and keys kept in sshr are
not exported`},
	{name: "desktop-entry", usage: "sshr desktop-entry [--remove]", short: "add sshr to the application menu",
		details: `a .desktop entry and icons on Linux, ~/Applications/sshr.app on macOS
(run again after an update, the bundle holds a copy)`},
	{name: "help", usage: "sshr help [command]", short: "show this help, or the options of one command"},
}

// findCommand returns the entry for a name or an alias
func findCommand(name string) *command {
	for i := range commands {
		c := &commands[i]
		if c.name == name {
			return c
		}
		for _, a := range c.aliases {
			if a == name {
				return c
			}
		}
	}
	return nil
}

func printUsage() { writeUsage(os.Stderr) }

// writeUsage prints one line per command
func writeUsage(w io.Writer) {
	fmt.Fprintln(w, "sshr - SSH host manager\n\nUsage: sshr <command> [options], sshr alone opens the app\n\nCommands:")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-15s %s\n", c.name, c.short)
	}
	fmt.Fprintln(w, `
sshr help <command> shows its options, --reuse or --no-reuse with any
command that connects shares one connection per host or not, overriding
the setting`)
}

// writeCommandHelp prints the usage and details of one command
func writeCommandHelp(w io.Writer, c *command) {
	fmt.Fprintln(w, "Usage: "+strings.ReplaceAll(c.usage, "\n", "\n       "))
	if len(c.aliases) > 0 {
		fmt.Fprintln(w, "Also:  "+strings.Join(c.aliases, ", "))
	}
	if c.details != "" {
		fmt.Fprintln(w, "\n"+c.details)
	} else {
		fmt.Fprintln(w, "\n"+c.short)
	}
}

func cmdHelp(args []string) {
	if len(args) == 0 {
		writeUsage(os.Stdout)
		return
	}
	c := findCommand(args[0])
	if c == nil {
		unknownCommand(args[0])
	}
	writeCommandHelp(os.Stdout, c)
}

// unknownCommand stops with the closest command names as a hint
func unknownCommand(name string) {
	fmt.Fprintf(os.Stderr, "sshr: unknown command %q\n", name)
	var names []string
	for _, c := range commands {
		names = append(names, c.name)
		names = append(names, c.aliases...)
	}
	if near := closest(name, names); len(near) > 0 {
		fmt.Fprintf(os.Stderr, "did you mean: sshr %s\n", strings.Join(near, ", sshr "))
	} else {
		fmt.Fprintln(os.Stderr, "sshr help lists the commands")
	}
	os.Exit(1)
}

// closest returns the candidates within a small edit distance of word,
// nearest first, a prefix of a candidate counts as near too
func closest(word string, candidates []string) []string {
	word = strings.ToLower(word)
	best := map[int][]string{}
	seen := map[string]bool{}
	for _, c := range candidates {
		if seen[c] {
			continue
		}
		seen[c] = true
		d := editDistance(word, strings.ToLower(c))
		if len(word) >= 2 && strings.HasPrefix(strings.ToLower(c), word) {
			d = 1
		}
		limit := 2
		if len(word) <= 3 {
			limit = 1
		}
		if d <= limit {
			best[d] = append(best[d], c)
		}
	}
	var out []string
	for d := 0; d <= 2 && len(out) < 3; d++ {
		for _, c := range best[d] {
			if len(out) < 3 {
				out = append(out, c)
			}
		}
	}
	return out
}

func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}

// hintStore is the store of this run, a host that is not found gets the
// closest saved names as a hint
var hintStore *app.Store

// hostHint returns the saved names closest to query
func hostHint(query string) []string {
	if hintStore == nil {
		return nil
	}
	hosts, err := hintStore.List()
	if err != nil {
		return nil
	}
	var names []string
	for _, h := range hosts {
		names = append(names, h.Name)
	}
	return closest(query, names)
}
