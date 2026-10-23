# Features: what, what for, why

Every sshr feature outside the GUI with four answers: what it is, what problem it closes, why it helps and why it is built this way, how to use each one is in [USAGE.md](USAGE.md), how secrets are protected in [SECURITY.md](SECURITY.md), the longer reasoning in [WHY.md](WHY.md) (Russian), the desktop app (internal/ui) is described by its developer, a new feature gets its section here in the same commit

## Hosts and the basic CLI

### Host list and the core commands
- **What:** `sshr add`, `list`, `rm`, `connect`, hosts kept as one 0600 JSON file each in `~/.sshr/vault`, a table with name, address, user, port, login and tags
- **What for:** stop keeping server addresses, users, ports and keys in your head, notes or shell history
- **Why it helps:** `sshr connect web` replaces a long ssh line, the same list feeds the app, the CLI, sync, MCP and the API
- **Why this way:** plain files on your machine work offline, survive any crash of sshr and can be backed up or read without it, one file per host keeps a broken file from taking the others with it

### Short help
- **What:** `sshr help` lists every command in one line each, `sshr help <command>` shows its usage, other names and options
- **What for:** the full help had grown to 115 lines, the command you look for scrolled away
- **Why it helps:** the overview fits one screen, the options of one command are one call away, nothing that was in the long help is lost
- **Why this way:** one table in the code feeds both views and the completion, so a new command cannot be listed in one place and forgotten in another

### Short command names
- **What:** `sshr import` and `sshr export` for `import-ssh-config` and `export-ssh-config`, the long names keep working
- **What for:** the longest commands to type were the ones for `~/.ssh/config`
- **Why it helps:** six to eleven fewer characters, the name says what it does, scripts that use the old names do not break
- **Why this way:** aliases in the same command table, not new commands, so both names share one code path and one help entry

### Hints on a typo
- **What:** an unknown command answers with the closest ones (`sshr tunel` gives `did you mean: sshr tunnel`), a host that is not found with the closest saved names
- **What for:** a typo used to end with the whole help or a bare "not found"
- **Why it helps:** the right name is on the screen, no trip to `sshr help` or `sshr list`
- **Why this way:** edit distance of at most two (one for short words) plus prefixes, at most three names, nothing is run on a guess, so a typo never connects to the wrong server

### Tab completion
- **What:** `sshr completion bash|zsh|fish` prints a script, Tab then completes commands, flags, saved host names, tags and forward names, install.sh puts it in place for bash and fish
- **What for:** host names, tags and forward names had to be typed out or looked up in `sshr list`
- **Why it helps:** `sshr conn<Tab> w<Tab>` instead of the whole line, names come from your own hosts, so a typo cannot reach the wrong server
- **Why this way:** the scripts are a few lines that call `sshr __complete`, the logic lives in Go with the command table, so it matches the installed version on every shell, files are completed where sshr has nothing to offer, as in send and get

### Recent hosts first
- **What:** `sshr connect` notes when a session ended after ssh had opened it, `sshr list --recent` puts the last connected hosts first with a LAST column ("3 h ago")
- **What for:** with many hosts the one you need is usually one of the last few
- **Why it helps:** the host is on the first line instead of somewhere in a long list, the plain `sshr list` stays as it was
- **Why this way:** the time is written only when ssh did not fail to connect (exit code other than 255), so failed attempts do not count, it stays on this machine and does not sync, otherwise every connect would be a change pushed to every device

### sshr show
- **What:** `sshr show <host>` prints the fields of a host and the exact ssh command `sshr connect` runs for it, quoted for a shell
- **What for:** when a connection does not work you need to know what sshr actually passes to ssh
- **Why it helps:** the line can be copied, run with `-v` added and compared with plain ssh, without reading the code
- **Why this way:** passwords never show because they reach ssh through the askpass socket and not the command line, each argument is quoted for a POSIX shell so the copied line runs as the same argv, a test runs it through sh, the lab connects with it through a jump host

### JSON output
- **What:** `--json` for `sshr list`, `sshr ping` and `sshr run`: hosts with the fields of the REST API, state, latency and reason per host, exit code, stdout and stderr per host
- **What for:** scripts, monitoring and other programs had to parse tables made for people
- **Why it helps:** `sshr list --json | jq` and `sshr run --json -t prod -- uptime` give data that does not break when a column is added
- **Why this way:** fixed field lists, the host part is app.HostSummary that the API already returns, so secrets cannot slip in, run prints one list at the end instead of a stream so the output is one valid JSON document

### Quick connect without saving
- **What:** `sshr connect user@host[:port]` or `ssh://user@host[:port]` connects to a destination that is not saved, then asks on a terminal for a name to save it under
- **What for:** a server you need once should not need `sshr add` first, and one you will need again should not need retyping
- **Why it helps:** the same command for both cases, saved hosts behave exactly as before
- **Why this way:** it only applies when no saved host matches and the text has a user, so a typo in a host name still gets the "did you mean" hint, a password in the address is refused because it would stay in the shell history, the address and user pass the same checks as a saved host, nothing is asked without a terminal

### Ambiguous names refused, short IDs
- **What:** a query that matches several hosts is refused with the list of matches, `sshr list` shows an 8 character ID
- **What for:** two hosts called "web" must never mean "connect to whichever came first"
- **Why it helps:** `rm` or `run` never hits the wrong server by accident
- **Why this way:** asking for the ID costs one retry, guessing can cost a production server

### Interactive login choice in `sshr add`
- **What:** without a login flag `sshr add` asks: key file (with a list of keys found in `~/.ssh`), saved password, password every time, key pasted into sshr, ssh agent
- **What for:** nobody remembers which of seven flags sets which login
- **Why it helps:** adding a host is one command and a few answers
- **Why this way:** with no terminal (a script) it stops instead of guessing, so automation always says what it wants

### Hardened host storage
- **What:** host files are written through a temp file and a rename, a damaged file is skipped with a warning, the host ID comes from the file name, ports outside 1-65535 and addresses or jump hops with shell or ssh config characters are refused, a host name can never become an ssh option
- **What for:** a crash, a hand edit or a synced host must not lose the list or run commands on your machine
- **Why it helps:** the vault stays readable and safe whatever ends up in it
- **Why this way:** values from files, sync and the API reach ssh command lines and `ProxyCommand`, which a shell runs, so they are checked on save and again before use

## Logging in

### Key files
- **What:** a host points at a private key file (`-k`), checked on save for a PRIVATE KEY header
- **What for:** the most common way to log in, with keys you already have
- **Why it helps:** a typo or a public key given by mistake fails when you save, not later at connect with a vague ssh error
- **Why this way:** ssh reads the file itself, sshr only passes `-i`, nothing is copied

### New keys and putting them on a host
- **What:** `sshr key new` makes an ed25519 key in `~/.ssh` with ssh-keygen, `sshr key install <host> [key.pub] [--use]` appends the public key to `authorized_keys` on the host and with `--use` switches the host to that key
- **What for:** moving a server from a password to a key took ssh-keygen, ssh-copy-id with the right port and jump hosts, then editing the host
- **Why it helps:** two commands, the install logs in the way the host already does, a saved password or a jump host included
- **Why this way:** ssh-keygen asks for the passphrase, so it never reaches a command line, an existing key is never overwritten, the public key goes to the server on stdin, so no quoting can break it, the remote script adds it once with umask 077, `--use` checks the private key is there before anything changes

### Saved passwords and ask mode
- **What:** a password sealed with XChaCha20-Poly1305 under a key from the system keychain, or nothing stored and ssh asks each time
- **What for:** routers, NAS boxes, cheap VPS panels and client machines where a key is not an option
- **Why it helps:** no more retyping, no password in a note or alias, no `sshpass` exposing it on the command line
- **Why this way:** sshr is its own askpass and serves the password over a one-shot socket, never in argv, the environment or a file, only the password prompt gets it and only once, so a wrong password does not feed fail2ban

### Keys stored in sshr
- **What:** a private key pasted into sshr is sealed like a password and served from an in-memory agent while ssh runs
- **What for:** keys that arrive as text from a client or a panel
- **Why it helps:** no key file to lose in backups or dotfile repos, a passphrase is asked once
- **Why this way:** ssh offers only this key and agent forwarding is off, so neither other keys nor the server can reach it

### Vault under a passphrase
- **What:** `sshr vault passphrase` keeps the vault key in a file wrapped with a passphrase instead of the system keychain, `sshr vault keychain` moves it back, off by default
- **What for:** servers, containers and minimal desktops have no Secret Service, saved passwords did not work there at all
- **Why it helps:** saved passwords and stored keys work on such a machine, the same key as before, so nothing has to be saved again
- **Why this way:** Argon2id with the parameters in the file makes a stolen file expensive to guess, the passphrase is asked once per run and never from stdin or in mcp, the keychain stays the default because it asks nothing and is not attackable offline

### Keys from an ssh agent
- **What:** a host uses the system agent, the 1Password SSH agent or any agent socket, with one chosen key
- **What for:** keys that should never be a file, in a password manager or on a hardware token
- **Why it helps:** approval per use, nothing to steal from disk, and no "Too many authentication failures" from agents holding many keys
- **Why this way:** sshr never holds the key, it tells ssh which agent and which public key to offer

### 1Password
- **What:** a host stores an `op://` reference to its password or key, sshr reads it with `op` on connect, a typed password can become a new 1Password item
- **What for:** teams and people whose secrets already live in 1Password
- **Why it helps:** one place for secrets, changes apply at once, access follows vault sharing and revocation
- **Why this way:** the `op` CLI handles unlock and Touch ID, the new item gets the password through stdin, never argv

### Bitwarden
- **What:** a host stores a Bitwarden item ID, `bw` reads the password or the SSH Key item on connect with `BW_SESSION`
- **What for:** Bitwarden and self-hosted Vaultwarden users
- **Why it helps:** the same as 1Password, nothing secret on the machine
- **Why this way:** the master password never passes through sshr, the key comes from the item JSON because `bw` has no command for it

### Password manager references stay local
- **What:** references never sync and are dropped when a synced host moves to another address, user, port or jump
- **What for:** one stolen device must not make the others read their secrets and send them to its server
- **Why it helps:** sync cannot turn into a way to collect your passwords
- **Why this way:** a synced password is a value you typed, a reference points at a secret only this machine can read, so only the machine itself may set it

## Connecting

### Jump hosts
- **What:** a host goes through saved bastions or `user@host:port` hops, chains included
- **What for:** servers in private networks reachable only through a bastion
- **Why it helps:** one command instead of two logins, keys stay on your machine, forwards, copies, `run` and paste follow the same path
- **Why this way:** saved hops run through sshr as `ProxyCommand` so each logs in with its own key or password, a host with a saved password or a key kept in sshr never uses `-J`, so a plain hop cannot see that password or be offered that key

### Gateway when the host does not answer
- **What:** a host can name a gateway, sshr connects directly and goes through the gateway only when the host does not answer, off by default per host, `sshr add --gateway` or `sshr gateway <host> <gateway>`
- **What for:** a server reachable directly at the office or on the VPN and only through a bastion from home
- **Why it helps:** one saved host works from both places, no second copy of it with `-J` and no editing it when you move
- **Why this way:** the check is the health check (a TCP connect and the SSH banner) before ssh starts, retrying after ssh fails would mean a second login prompt in the middle of a session, a saved password stays sealed for the gateway too, so a gateway written into the file by hand does not get it

### tmux and zellij sessions
- **What:** connect attaches to a session on the server or creates it
- **What for:** sleep, Wi-Fi switches and VPN drops kill an ssh shell and its jobs
- **Why it helps:** the job keeps running and you return to the same place
- **Why this way:** it works over plain ssh on every OS with forwards and images, so it covers most of what people want from mosh without its costs

### Port forwards and tunnels
- **What:** named `-L`, `-R` and `-D` forwards per host, opened with a shell or alone with `sshr tunnel`
- **What for:** databases, admin panels and internal services that must not be public
- **Why it helps:** `sshr tunnel prod db` instead of remembering `-L 5432:localhost:5432`, `-R` for webhooks and showing a local dev server, `-D` as a SOCKS proxy
- **Why this way:** `ExitOnForwardFailure` makes a busy port fail at once, and a stopped sshr stops its ssh too, so no tunnel is left holding a port

### Shared connections
- **What:** sessions to one host share a connection (ControlMaster) for 10 minutes, off by default
- **What for:** many terminals, copies and tunnels to the same server
- **Why it helps:** the second opens in about 0.1 s instead of 0.65 s with no new password prompt
- **Why this way:** off by default because one drop closes all of them and an open master lets your account in without a password

### mosh
- **What:** connect through mosh, falling back to ssh when it fails, off by default
- **What for:** mobile links and laptops that sleep
- **Why it helps:** the shell survives network changes and typing echoes at once
- **Why this way:** off by default, it needs UDP ports and mosh-server, carries no forwards and has no Windows client

### Health check
- **What:** a TCP connect and the SSH banner with the round trip, in `sshr ping`, `list --ping` and a dot in the app, off by default
- **What for:** know which servers are down before waiting on an ssh timeout
- **Why it helps:** a glance at the list shows what answers
- **Why this way:** no login is tried, but sshd still logs each check and strict fail2ban modes count it, so it is off until you choose it, a host that is down says why (the name does not resolve, refused, no answer, unreachable, no SSH banner) and `--json` gives the same as one word for scripts

## Moving hosts in and out

### Server key check
- **What:** `sshr ping --keys` reads the key each server shows and compares it with `~/.ssh/known_hosts`: known, unknown or changed, with its SHA256 fingerprint, a changed key makes ping exit 1
- **What for:** a reinstalled server or someone in between shows up as "REMOTE HOST IDENTIFICATION HAS CHANGED" only when you connect, in the middle of work
- **Why it helps:** one command checks every host before you log in, the fingerprint can be compared with the one the server's admin gives
- **Why this way:** only the key exchange runs, sshr stops before any login, it reads the user's own known_hosts (hashed entries too) and never writes to it, so there is no second trust store, hosts behind a jump host are not checked because their key is only visible through it

### Import from ssh config
- **What:** every `Host` of `~/.ssh/config` and its includes becomes a host, with keys, agent, jumps and forwards
- **What for:** starting with the hosts you already have
- **Why it helps:** one command instead of retyping, running it again adds only new ones
- **Why this way:** each host is resolved with `ssh -G`, so `Match` and defaults come out exactly as ssh sees them, a parser of our own would differ

### Export to ssh config
- **What:** `~/.sshr/ssh_config` written from the hosts and included first in `~/.ssh/config`, kept current, off by default
- **What for:** hosts added in sshr should work in ssh, scp, rsync, git and editors
- **Why it helps:** no second list to maintain
- **Why this way:** one Include line in your file, everything else in sshr's own file, secrets and values that could add ssh options never get there, a linked config is not edited

### Sync between devices
- **What:** hosts sync through your own `sshr-sync` server, end to end encrypted with per-device keys and signed manifests
- **What for:** the same list on every machine without drift
- **Why it helps:** add a host once and it appears everywhere, a host changed on two devices keeps both versions
- **Why this way:** the server stores only ciphertext and cannot read hosts, add a device or rewrite history, devices are approved by comparing fingerprints, keys stored in sshr stay on their device

### Safe saves from several sshr processes
- **What:** every change of hosts runs under a lock file, the sync takes it per host from reading the local version to writing the remote one, one sync run at a time on a machine
- **What for:** the app, the CLI, `sshr serve`, `sshr mcp` and a sync can run at the same time
- **Why it helps:** an edit saved in the app during a sync is never overwritten, a key rotation is never undone by a second sync started at the same moment
- **Why this way:** one lock for all hosts because the export and conflict copies touch several at once and a write takes milliseconds, a waiting save gives up after 30 s and names the pid that holds the lock, a second sync stops at once since it would have nothing new to do

### Sync server
- **What:** `sshr-sync` with TLS 1.3, Let's Encrypt or your own certificate, or plain HTTP behind a proxy on loopback
- **What for:** run the sync backend yourself
- **Why it helps:** no vendor cloud, a small binary with a data folder
- **Why this way:** tokens are stored hashed, joins are rate limited, pushes are compare-and-swap so devices cannot overwrite each other

### Tags and search
- **What:** tags per host, search over names, addresses, users and tags, in the CLI and the app
- **What for:** past a dozen hosts you remember a role, not a name
- **Why it helps:** find a host in two keystrokes, act on a group with `sshr run -t`
- **Why this way:** lower case letters, digits and `.-_` only, so a tag reads the same in a search, a file and a shell

## Working on servers

### Copying files
- **What:** `sshr send` and `sshr get` over scp with the host's login, jumps and shared connection, `--legacy` for servers without SFTP
- **What for:** copying to hosts behind bastions or with agent keys without rebuilding scp options
- **Why it helps:** the same short command as connect, folders included
- **Why this way:** scp from OpenSSH behaves the way people know, the old protocol covers minimal servers

### One command on many hosts
- **What:** `sshr run` on hosts by name or tag, in parallel, each output as one block, a list of failures
- **What for:** checking or fixing many servers at once
- **Why it helps:** one command instead of a loop of logins, a clear answer which host failed
- **Why this way:** each host uses its own login and jump, the command is stopped on the server after the timeout, hosts that ask for a password are skipped instead of hanging

### Clipboard images to a server
- **What:** `sshr paste` and the app's Send image upload the clipboard image or a file and give its path on the server, removed after 15 minutes
- **What for:** a screenshot pasted into a remote session is a path on your disk the server cannot open
- **Why it helps:** remote AI tools, editors and scripts get a file they can read
- **Why this way:** the server needs only `sh`, the clipboard is read with tools the OS already has (wl-paste, xclip, osascript, PowerShell), so the binary needs no cgo

## For other programs

### Extensions
- **What:** `sshr ext install <git url or folder>` shows what an extension is and asks, then `sshr <name>` runs it, `sshr ext list` and `sshr ext remove` manage them, an extension is a program in `~/.sshr/extensions/<name>/` with a manifest `sshr-ext.json`, written in any language
- **What for:** your own commands under the same word `sshr` without a fork or a change of sshr, a deploy helper, a report of your hosts, a wrapper for your cloud
- **Why it helps:** the tools around your hosts live in one place, a built-in command never changes whatever you install, and the extension can read your hosts back with `sshr list --json`
- **Import sources:** an extension of kind `import` prints hosts as JSON and `sshr ext import <name>` saves them, for Remmina (`extensions/remmina`), PuTTY on Linux and macOS (`extensions/putty`), Termius or a company inventory, only a fixed list of fields is read and never a password or key, a second import skips hosts that are already there
- **Why this way:** an executable with a fixed protocol, not a Go plugin or WASM, so any language works and a crash stays in its own process, sshr asks before it installs and shows the manifest, the command, the commit and a hash, every file of the folder is pinned and a changed file stops the run until you install it again, the extension never gets a password, key or secret reference or the askpass and password manager variables of sshr, it is still a program that runs as you, which is said in `sshr ext install` and in [SECURITY.md](SECURITY.md)

### MCP server for AI assistants
- **What:** `sshr mcp` gives Claude Code, Codex or Cursor the tools list_hosts, upload_file and run_command, setup and limits in [MCP.md](MCP.md)
- **What for:** assistants asked to read logs or check a server
- **Why it helps:** no addresses or keys pasted into a chat, the assistant uses your saved logins without seeing them
- **Why this way:** run_command is off by default and marked destructive, nothing listens on the network, output and time are capped, every command is logged

### Local REST API
- **What:** `sshr serve` with endpoints for hosts, the ssh command line, uploads, runs and tunnels
- **What for:** editor plugins, launchers and scripts
- **Why it helps:** they integrate without parsing CLI output
- **Why this way:** a 0600 unix socket by default, a loopback port only with a token, web pages and DNS rebinding are refused, no secrets in or out

### Commands only on chosen hosts
- **What:** `sshr commands only` limits commands from `sshr mcp` and `sshr serve` to the hosts of `sshr commands allow <host>`, `sshr commands all` goes back, `sshr commands list` shows them, `--listed-hosts-only` and `--all-hosts` for one run, off by default
- **What for:** an assistant that may run commands on a test box should not reach production with the same switch
- **Why it helps:** commands stay on for the servers you chose and the rest are refused with a message how to allow them
- **Why this way:** the list is in settings.json, which never syncs, so another device cannot add a host here, each entry is bound to where the host pointed when it was allowed, a host repointed later (on another device too) is refused until it is allowed again, off by default since every host took commands before and a new server would need one more step

### Audit log of assistants and scripts
- **What:** `sshr mcp --audit` and `sshr serve --audit` (or `"audit_log": true`) write every upload, command, host change and tunnel to `~/.sshr/audit.jsonl`, one JSON line when it starts and one when it ends, with the client, the host and the exit code, off by default
- **What for:** an assistant or a script acts on your servers while you look elsewhere, afterwards you want to know what it did and where
- **Why it helps:** one file answers which host got which command at what time and from which client, a start without an end shows a run that was cut off
- **Why this way:** a command is kept as its length, first word and a keyed hash unless `"audit_commands": "full"`, a command may carry a password, lines are appended under a lock so several sshr processes never mix them, the file moves to `.1` at `audit_max_mb` (10 MB), an action whose start cannot be written does not run, the log is off by default because it is one more file that grows and tells which servers were used when

## Installing

### install.sh
- **What:** one line installs sshr on Linux and macOS into `~/.local/bin`, a release binary checked against `sha256sums.txt` or a build from source, a PATH line, `--uninstall`
- **What for:** installing without root or a package manager
- **Why it helps:** one command, and `--uninstall` removes everything it added
- **Why this way:** an unchecked binary is never installed, the GUI falls back to the CLI when build tools are missing, packages are planned in #17

### Release files
- **What:** a tag like `v1.2.3` builds the CLI for linux, darwin and windows on amd64 and arm64 in GitHub Actions, publishes `sshr_<os>_<arch>` (`.exe` on Windows) with `sha256sums.txt` and signs them with a build attestation, `scripts/release.sh v1.2.3` makes the same files on any machine
- **What for:** install.sh and the packages of #17 (AUR, Homebrew, Scoop, nixpkgs) need a file with a known name and a checksum to take
- **Why it helps:** installing needs no Go and no build tools, a tampered file is found by the checksum, and `gh attestation verify sshr_linux_amd64 --repo klovbin/sshr` shows which commit and workflow built it
- **Why this way:** the tests run first, a failing tag publishes nothing, the CLI is built without cgo so one machine builds all six files, the version is set at build time and the binary reports it, the attestation needs no key to store and lose, the GUI is not in these files, it needs cgo and a build per system

### Application menu and icons
- **What:** `sshr desktop-entry` adds sshr to the Linux menu and makes `~/Applications/sshr.app` on macOS, the Windows exe carries the icon
- **What for:** start the app like any other program with its own icon
- **Why it helps:** no terminal needed to open the GUI
- **Why this way:** the icons are inside the binary, so nothing is downloaded, the macOS bundle holds a copy because the Dock shows a bundle icon only for a program inside it

### Cross-platform CI
- **What:** every push runs the tests on Linux, macOS and Windows and connects to a real sshd with keys, a jump host, copies, `run` and on macOS a saved password
- **What for:** sshr has to work on three systems the developers do not all use
- **Why it helps:** Windows and macOS bugs show up before users see them, several did
- **Why this way:** emulation (Wine) misses real Windows behavior, hosted runners are the real systems
