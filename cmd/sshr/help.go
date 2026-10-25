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
	{name: "list", aliases: []string{"ls"}, usage: "sshr list [options] [search...]", short: "list saved hosts",
		details: `Search words match the name, address, user and tags,
tag:prod or #prod matches that tag only

Options:
  --recent     the hosts you connected to last first, with how long ago
  --json       the hosts as JSON, the same fields as the REST API, no secrets
  --ping       also show whether each host answers
  --no-ping    do not, when health_check is on in the settings

Examples:
  sshr list
  sshr list --recent
  sshr list #prod web`},
	{name: "add", usage: "sshr add <host> -u <user> [options]", short: "add a host",
		details: `How to log in, pick one, sshr asks when none is given:
  -k, --key <file>             a private key file
  --key-stdin                  a private key read from stdin, kept encrypted in sshr
  --no-key                     a password, kept encrypted with the system keychain
  --ask-password               no password saved, ssh asks on every connect
  --agent [system|1password|<socket>]
                               a key from an ssh agent
  --agent-key <fingerprint>    which key of the agent, its comment works too
  --op-password <op://...>     the password from 1Password on every connect
  --op-key <op://...>          the private key from 1Password
  --store 1password            with --no-key: save the password as a new 1Password
                               item, --op-vault <name> picks the vault
  --bw-password <item id>      the password from Bitwarden (bw, BW_SESSION set)
  --bw-key <item id>           the private key from Bitwarden

Other options:
  -n, --name <name>            the name in the list, the address by default
  -p, --port <port>            22 by default
  -J, --jump <a,b>             jump hosts: saved names or [user@]host[:port]
  --gateway <a,b>              go through these only when the host does not
                               answer directly, checked on each connect
  --session tmux|zellij        attach to that session on connect
  -t, --tag <tags>             tags, comma separated

Examples:
  sshr add 10.0.0.7 -u deploy -n web
  sshr add 10.0.0.7 -u deploy -k ~/.ssh/id_ed25519 -t prod
  sshr add db.internal -u app -J web --ask-password`},
	{name: "show", usage: "sshr show <name or id>", short: "show a host and the ssh command it runs",
		details: `Prints the fields of the host and the exact ssh command sshr connect runs,
quoted so it can be copied, passwords never show, they reach ssh through
a socket and not the command line, a host with a gateway shows the direct
way, connect goes through the gateway when the host does not answer

Examples:
  sshr show web`},
	{name: "key", usage: `sshr key new [name] [--no-passphrase]
sshr key new [name] --sk [--resident] [--verify-required]
sshr key install <host> [public key file] [--use]`, short: "make a key, put it on a host",
		details: `new makes an ed25519 key in ~/.ssh (sshr_ed25519 by default) with
ssh-keygen, which asks for the passphrase, an existing key is never
overwritten

new --sk makes the key on a FIDO token (YubiKey and the like), the
private half never leaves it, ~/.ssh gets a handle (sshr_sk by default)
that is useless without the token, ed25519-sk first, ecdsa-sk when the
token has no Ed25519, every login asks for a touch, the server needs
OpenSSH 8.2 or newer, the handle is used as a key file (-k), it cannot be
pasted into sshr

install appends a public key to ~/.ssh/authorized_keys on the host,
logging in the way the host does (a password is asked or taken from
sshr), a key already there is not added twice, the default is the first
of ~/.ssh/sshr_ed25519.pub, id_ed25519.pub, id_ecdsa.pub, id_rsa.pub

Options:
  --no-passphrase   new: no passphrase on the key or the handle of --sk
  --sk              new: the key lives on a FIDO token
  --resident        new --sk: keep the key on the token, ssh-keygen -K brings
                    it to a new machine
  --verify-required new --sk: ask the PIN of the token on every login too
  --use             install: the host logs in with this key from then on

Examples:
  sshr key new
  sshr key new --sk --verify-required
  sshr key install web --use`},
	{name: "rm", aliases: []string{"remove"}, usage: "sshr rm <name or id>", short: "remove a host"},
	{name: "connect", aliases: []string{"ssh"}, usage: "sshr connect [options] <name or id>", short: "ssh into a host",
		details: `Options:
  --mosh             connect with mosh, also on when mosh is on in the settings
  --ssh              plain ssh even when mosh is on in the settings
  --plain            skip the tmux or zellij session of the host
  -F <forward>|all   also open saved forwards
  --local-commands   run the commands of sshr hooks for this host, also on
                     when local_commands is on in the settings
  --no-local-commands  do not run them even when the setting is on

A destination that is not saved works too: user@host[:port] or
ssh://user@host[:port] connects once with the default keys, the agent or a
password prompt, then asks on a terminal whether to save it

Examples:
  sshr connect web
  sshr connect -F db web
  sshr connect deploy@10.0.0.7:2222`},
	{name: "ping", usage: "sshr ping [--keys] [--json] [name or id...]", short: "check whether hosts answer",
		details: `Opens a TCP connection and reads the SSH banner, does not log in,
all hosts when none is named, exits 1 when one is down

Options:
  --keys   also read the server key (key exchange only, no login) and
           compare it with ~/.ssh/known_hosts: known, unknown or changed,
           a changed key also makes ping exit 1
  --json   state, latency in ms, reason and cause per host as JSON, the
           cause is one word: dns, refused, timeout, unreachable,
           no_banner, jump, alias or other`},
	{name: "tag", usage: "sshr tag <name or id> [+tag|-tag|tag...]", short: "show, add or remove tags",
		details: `Examples:
  sshr tag web               show the tags
  sshr tag web +prod eu      add prod and eu
  sshr tag web -eu           remove eu`},
	{name: "gateway", usage: "sshr gateway <name or id> [<gateway>|--off]", short: "fall back to a jump host when a host does not answer",
		details: `With a gateway, connect, run, send, get and tunnel check the host
directly first (a TCP connect and the SSH banner, up to 3 s each) and go
through the gateway only when it does not answer, off by default: a host
that is down directly costs that wait on every connect, a host with jump
hosts always goes through them and has no gateway

Examples:
  sshr gateway db                show it
  sshr gateway db bastion        through the saved host bastion
  sshr gateway db --off          connect directly again`},
	{name: "run", usage: "sshr run [options] [name...] -- <command>", short: "run a command on many hosts",
		details: `Runs on the named hosts and on the hosts that have all the -t tags,
prints each host's output as a block, exits 1 when one fails

Options:
  -t <tag>         hosts with this tag, repeat for more tags
  -j <N>           how many at once, 8 by default
  --timeout <s>    stop the command after s seconds
  --json           one JSON list at the end: exit code, stdout, stderr per host

Examples:
  sshr run -t prod -- uptime
  sshr run web db --timeout 30 -- 'df -h /'`},
	{name: "send", usage: "sshr send <name or id> <path>... [options]", short: "copy files to a host",
		details: `Copies files and folders with scp and the host's own key, password and
jump hosts

Options:
  --to <folder>    where on the host, the home folder by default
  --legacy         the old scp protocol, for servers without SFTP

Examples:
  sshr send web ./site --to /var/www`},
	{name: "get", usage: "sshr get <name or id> <remote path>... [options]", short: "copy files from a host",
		details: `Options:
  --to <folder>    where here, the current folder by default
  --legacy         the old scp protocol, for servers without SFTP

Examples:
  sshr get web /var/log/nginx/error.log`},
	{name: "forward", aliases: []string{"fwd"}, usage: `sshr forward <host>
sshr forward add <host> <name> -L|-R|-D <spec>
sshr forward rm <host> <name>`, short: "list, save or remove port forwards",
		details: `-L, -R and -D take what ssh takes after them

Examples:
  sshr forward add web db -L 5432:localhost:5432
  sshr forward add web socks -D 1080`},
	{name: "tunnel", usage: "sshr tunnel <host> [names...]", short: "open forwards without a shell",
		details: `Opens the named forwards, all of them when none is named,
Ctrl+C closes them`},
	{name: "close", usage: "sshr close <name or id>", short: "close the shared connection to a host"},
	{name: "paste", usage: "sshr paste [options] <name or id>", short: "upload the clipboard image",
		details: `Uploads the clipboard image to the host and prints its path there,
the file is removed from the server after 15 minutes

Options:
  -c          also copy that path to the clipboard
  -f <file>   upload this file instead of the clipboard`},
	{name: "mcp", usage: "sshr mcp [options]", short: "MCP server for AI assistants",
		details: `Talks over stdin and stdout: list hosts, upload files, run commands

Options:
  --allow-commands   allow run_command, off by default (mcp_commands setting)
  --no-commands      refuse it even when the setting is on
  --confirm-commands   ask before every command through the client, a client
                       that cannot ask gets them refused (confirm_commands)
  --no-confirm         run without asking even when the setting is on
  --listed-hosts-only  run_command only on hosts of sshr commands allow
  --all-hosts          on every host even when commands_listed_only is set
  --audit            keep ~/.sshr/audit.jsonl, off by default (audit_log setting)
  --no-audit         keep no audit log even when the setting is on`},
	{name: "serve", usage: "sshr serve [options]", short: "local REST API",
		details: `Never returns secrets, commands are off by default

Options:
  --listen unix:<path>       a unix socket, the default
  --listen 127.0.0.1:<port>  a loopback port, needs the token from ~/.sshr/api-token
  --allow-commands           allow POST /run, off by default (api_commands setting)
  --no-commands              refuse it even when the setting is on
  --listed-hosts-only        POST /run only on hosts of sshr commands allow
  --all-hosts                on every host even when commands_listed_only is set
  --audit                    keep ~/.sshr/audit.jsonl, off by default (audit_log setting)
  --no-audit                 keep no audit log even when the setting is on`},
	{name: "sync", usage: "sshr sync [init|invite|join|pending|approve|pull|push|status|remove-device|leave]", short: "sync hosts between devices",
		details: `End to end encrypted through an sshr-sync server, sshr sync help shows
the steps`},
	{name: "import", aliases: []string{"import-ssh-config"}, usage: "sshr import [--dry-run]", short: "add the hosts of ~/.ssh/config",
		details: `Takes keys, agents, jump hosts and forwards along, skips hosts that are
already saved

Options:
  --dry-run   show what would be added`},
	{name: "export", aliases: []string{"export-ssh-config"}, usage: "sshr export [options]", short: "write the hosts as ssh config",
		details: `Prints the hosts as ssh config, passwords and keys kept in sshr are
not exported

Options:
  --install     write ~/.sshr/ssh_config, include it from ~/.ssh/config and
                keep it up to date, then ssh, scp and editors know the names
  --uninstall   remove both`},
	{name: "desktop-entry", usage: "sshr desktop-entry [--remove]", short: "add sshr to the application menu",
		details: `Writes a .desktop entry and icons on Linux, ~/Applications/sshr.app on
macOS, run it again after an update

Options:
  --remove   take it out of the menu`},
	{name: "commands", usage: "sshr commands list|only|all|allow <host>|deny <host>", short: "hosts assistants and scripts may run commands on",
		details: `Commands through sshr mcp and sshr serve are off until --allow-commands or
the setting turns them on, then every host takes them. only limits them to
the hosts allowed here, all goes back to every host (commands_listed_only
setting, --listed-hosts-only and --all-hosts for one run). allow lists a
host for where it points now, a host that points elsewhere later, for
example changed on another device, is refused until it is allowed again.
The list is in settings.json and never syncs`},
	{name: "hwkey", usage: `sshr hwkey status
sshr hwkey require <host>... | --all
sshr hwkey off [<host>...]
sshr hwkey check <host>`, short: "hosts that connect only with a key on a hardware token",
		details: `require lists hosts that connect only with a key on a FIDO token (a
handle from sshr key new --sk as the key file, or an sk key of the agent),
--all asks it of every host. Such a host is refused when it would log in
with a password or a key outside a token, ssh gets only sk key types, no
password and no shared connection, there is no way around it for one
connect. off takes hosts off the list, without hosts it turns the
requirement off. The list is in settings.json and never syncs, a stolen
sync device cannot turn it off. The server decides in the end, sshr only
keeps itself from logging in another way. check reads authorized_keys on
the host, lists the keys that are not on a token and prints the lines of
sshd_config that turn off passwords and the other ways in, keys sshd
takes from other files or a command are not read, it changes nothing
there`},
	{name: "hooks", usage: `sshr hooks list
sshr hooks on|off
sshr hooks set <host> before|after <command>
sshr hooks unset <host> [before|after]`, short: "commands to run on this machine around a session",
		details: `A command before runs before ssh starts, to bring a VPN up or unlock a
key, if it fails sshr does not connect, a command after runs when the
session ends and gets its exit code in SSHR_EXIT. Both run through the
shell of this machine with SSHR_HOST_NAME, SSHR_HOST, SSHR_PORT, SSHR_USER
and SSHR_HOST_ID set. They are off until sshr hooks on (local_commands
setting, connect --local-commands for one run). They live in settings.json,
which never syncs, no import, sshr serve, sshr mcp or extension sets them,
so a command never comes from another machine

Examples:
  sshr hooks set web before "wg-quick up office"
  sshr hooks set web after "wg-quick down office"
  sshr hooks on`},
	{name: "vault", usage: `sshr vault status|passphrase|keychain|recovery|slots
sshr vault add-token [--label <name>] [--pin]
sshr vault remove-slot <id>`, short: "keep the vault key in the keychain, under a passphrase or on a security key",
		details: `The vault key seals saved passwords and keys stored in sshr. It lives in
the system keychain, passphrase moves it into ~/.sshr/vault/vault-key.json
wrapped with a passphrase (Argon2id) for a machine without a keychain, off by
default: the passphrase is asked once per run, a forgotten one loses every
saved secret, and the file can be attacked offline, the copy in the keychain
is removed, a keychain that is locked keeps it and sshr says so, keychain
moves the key back and removes the file, the keys of the sync device move
along. recovery makes a recovery code for the vault under a passphrase:
random groups of letters and digits shown once, the passphrase prompt takes
the code instead of the passphrase, a typo is named by its group, the code
cannot be guessed offline, write it down and keep it away from the machine,
a new code replaces the old one, after the code opened the vault sshr gives
a new one on the terminal. add-token adds the one plugged FIDO2 security key
on Linux and macOS through fido2-cred and fido2-assert of libfido2: the
vault then opens with a touch and no question, without the key it asks the
passphrase or the recovery code, the first key comes with a recovery code,
slots lists what opens the vault, remove-slot removes one, a passphrase slot
can go once a key and a recovery code are there, then a copy of ~/.sshr
opens nothing without the key, the last way in that is not a key stays
unless two keys are there, --pin asks the PIN of the key every time the
vault opens, a stolen key then opens nothing without its PIN, a key with a
PIN set may ask it once to make its credential

Examples:
  sshr vault status
  sshr vault passphrase
  sshr vault recovery
  sshr vault add-token --label yubikey
  sshr vault slots
  sshr vault remove-slot 1a2b3c4d
  sshr vault keychain`},
	{name: "ext", usage: `sshr ext install <git url or folder> [--yes]
sshr ext import <name> [args...]
sshr ext list
sshr ext remove <name>`, short: "install, list and remove extensions",
		details: `An extension is a program in ~/.sshr/extensions/<name>/ that sshr runs
as sshr <name> when no command of sshr has that name, a built-in command
always wins

install takes an https or ssh git address or a folder, shows the manifest,
the command it will run, the commit and a hash of the files, and asks
before it installs, an extension runs as you and can do anything you can,
sshr gives it no password, key or secret reference, installing it again
is how you trust files you changed

import runs an extension that lists hosts (kind import), for example one
that reads PuTTY sessions, and saves what it prints, a host imported
before is left as it is, passwords and keys it prints are not read

sshr runs an extension only while its files are the ones that were
installed, a git pull in its folder stops it until you install it again

Options:
  --yes   install: do not ask, for scripts

Examples:
  sshr ext install https://github.com/someone/sshr-hello.git
  sshr ext install ./my-extension --yes
  sshr ext import putty
  sshr ext list
  sshr ext remove hello`},
	{name: "completion", usage: "sshr completion bash|zsh|fish", short: "Tab completion for your shell",
		details: `Prints a script that completes commands, options, host names, tags and
forwards, install.sh puts it in place for bash and fish

Examples:
  sshr completion fish > ~/.config/fish/completions/sshr.fish
  echo 'source <(sshr completion zsh)' >> ~/.zshrc`},
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
		fmt.Fprintln(w, "Also as: sshr "+strings.Join(c.aliases, ", sshr "))
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
