# Features: what, what for, why

Every sshr feature outside the GUI with four answers: what it is, what problem it closes, why it helps and why it is built this way, how to use each one is in [USAGE.md](USAGE.md), how secrets are protected in [SECURITY.md](SECURITY.md), the longer reasoning in [WHY.md](WHY.md) (Russian), the desktop app (internal/ui) is described by its developer, a new feature gets its section here in the same commit

## Hosts and the basic CLI

### Host list and the core commands
- **What:** `sshr add`, `list`, `rm`, `connect`, hosts kept as one 0600 JSON file each in `~/.sshr/vault`, a table with name, address, user, port, login and tags
- **What for:** stop keeping server addresses, users, ports and keys in your head, notes or shell history
- **Why it helps:** `sshr connect web` replaces a long ssh line, the same list feeds the app, the CLI, sync, MCP and the API
- **Why this way:** plain files on your machine work offline, survive any crash of sshr and can be backed up or read without it, one file per host keeps a broken file from taking the others with it

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
- **Why this way:** saved hops run through sshr as `ProxyCommand` so each logs in with its own key or password, a host with a saved password never uses `-J`, so a plain hop cannot see that password

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
- **Why this way:** no login is tried, but sshd still logs each check and strict fail2ban modes count it, so it is off until you choose it

## Moving hosts in and out

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

### MCP server for AI assistants
- **What:** `sshr mcp` gives Claude Code, Codex or Cursor the tools list_hosts, upload_file and run_command
- **What for:** assistants asked to read logs or check a server
- **Why it helps:** no addresses or keys pasted into a chat, the assistant uses your saved logins without seeing them
- **Why this way:** run_command is off by default and marked destructive, nothing listens on the network, output and time are capped, every command is logged

### Local REST API
- **What:** `sshr serve` with endpoints for hosts, the ssh command line, uploads, runs and tunnels
- **What for:** editor plugins, launchers and scripts
- **Why it helps:** they integrate without parsing CLI output
- **Why this way:** a 0600 unix socket by default, a loopback port only with a token, web pages and DNS rebinding are refused, no secrets in or out

## Installing

### install.sh
- **What:** one line installs sshr on Linux and macOS into `~/.local/bin`, a release binary checked against `sha256sums.txt` or a build from source, a PATH line, `--uninstall`
- **What for:** installing without root or a package manager
- **Why it helps:** one command, and `--uninstall` removes everything it added
- **Why this way:** an unchecked binary is never installed, the GUI falls back to the CLI when build tools are missing, packages are planned in #17

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
