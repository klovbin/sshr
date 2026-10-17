<p align="center"><img src="assets/icons/sshr-logo.png" width="128" height="128" alt="sshr logo"></p>

# sshr

SSH host manager for Linux, macOS and Windows: a desktop app and a CLI in one binary, hosts stay on your machine (`~/.sshr/vault`), connections go through the system `ssh`, nothing is installed on servers, anything with a cost is off by default

How secrets are protected: [docs/SECURITY.md](docs/SECURITY.md), plans: [docs/ROADMAP.md](docs/ROADMAP.md), reasons: [docs/WHY.md](docs/WHY.md) (Russian)

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/klovbin/sshr/main/install.sh | sh
```

Linux and macOS, into `~/.local/bin`, no root, takes a release binary when its checksum matches, otherwise builds from source (Go 1.21+, the GUI also needs a C compiler and on Linux Wayland/X11 and Vulkan headers), adds `~/.local/bin` to `PATH` and sshr to the application menu, options: `--prefix`, `--cli-only`, `--no-modify-path`, `--uninstall`, see `sh install.sh --help`

Windows: `go build -o sshr.exe ./cmd/sshr`, packages (AUR, Homebrew, Scoop, nixpkgs) are planned in [#17](https://github.com/klovbin/sshr/issues/17)

### Icon and application menu

`sshr desktop-entry` adds sshr to the menu (`--remove` takes it out): a `.desktop` entry on Linux, `~/Applications/sshr.app` on macOS (it holds a copy of sshr, run again after an update, `install.sh` does), on Windows the icon is built into `sshr.exe`

## Usage

```sh
sshr                                   # the app
sshr add 10.0.0.7 -u app -n web        # asks how to log in
sshr add 10.0.0.7 -u app -k ~/.ssh/id_ed25519
sshr list
sshr connect web
sshr rm web
```

## Tags and search

```sh
sshr add 10.0.0.7 -u app -n web -t prod,web
sshr tag web +eu -web          # add eu, remove web
sshr list prod                 # name, address, user or tag contains "prod"
sshr list '#prod' db           # exact tag prod and "db" anywhere
```

App: **Tags** in the host form, the search field above the list takes the same words. Tags sync with the hosts

## Copying files

```sh
sshr send web report.pdf logs/ --to /srv/in   # to the home folder without --to
sshr get web /var/log/nginx --to ./logs       # to the current folder without --to
```

scp with the host's own key, password, jump hosts and shared connection, folders copy whole, `--legacy` for servers without SFTP

## Running a command on many hosts

```sh
sshr run -t prod -- uptime                  # every host tagged prod
sshr run web db --timeout 30 -- 'df -h /'   # by name
```

8 hosts at a time (`-j`), each host's output as a block, exit 1 when one fails, the command is stopped on the server after `--timeout` (60 s), hosts that ask for a password are skipped

## Importing ~/.ssh/config

```sh
sshr import-ssh-config --dry-run
sshr import-ssh-config
```

App: **Settings → Import**, every `Host` of `~/.ssh/config` and its `Include`s becomes a host, resolved with `ssh -G`, so `Match` and `Host *` apply as in ssh, carries over address, user, port, `IdentityFile`, `IdentityAgent`, `ProxyJump` and forwards, patterns and hosts sshr already has are skipped, a host with `ProxyCommand` keeps its alias as the address

## Exporting to ~/.ssh/config

```sh
sshr export-ssh-config               # print
sshr export-ssh-config --install     # write ~/.sshr/ssh_config and include it
sshr export-ssh-config --uninstall
```

App: **Settings → Import → Export**, off by default, it edits your `~/.ssh/config`: adds `Include ~/.sshr/ssh_config` as the first line and rewrites that file on every change, so `ssh my-box`, `scp` and editors find the hosts, passwords and keys kept in sshr are not exported, names your config already has are skipped, a linked `~/.ssh/config` is not edited, sshr prints the line instead

## Passwords

```sh
sshr add db.example.com -u admin --no-key         # saved, encrypted with a key from the system keychain
sshr add db.example.com -u admin --ask-password   # nothing saved, ssh asks
```

A saved password reaches ssh through sshr's own askpass, never through a file, argv or the environment, it needs a system keychain, without one only ask mode and keys work

## Keys stored in sshr

```sh
sshr add web -u deploy --key-stdin < key
```

The key is sealed like a password, no file in `~/.ssh`, a passphrase is asked once, on connect sshr serves it from an in-memory agent, ssh offers only this key

## Keys from an ssh agent

```sh
sshr add web -u deploy --agent                              # SSH_AUTH_SOCK
sshr add web -u deploy --agent 1password --agent-key work   # the 1Password SSH agent
sshr add web -u deploy --agent /path/agent.sock --agent-key SHA256:...
```

`--agent-key` picks one key by fingerprint or comment, servers stop after about six keys

## Passwords and keys in 1Password

```sh
sshr add web -u deploy --op-password op://Private/web/password
sshr add web -u deploy --no-key --store 1password --op-vault Servers   # creates the item
sshr add web -u deploy --op-key "op://Private/web key/private key"
```

Needs the `op` CLI signed in, each connect reads the item. 1Password references do not sync between devices

## Passwords and keys in Bitwarden

```sh
export BW_SESSION="$(bw unlock --raw)"
sshr add web -u deploy --bw-password <item id>   # bw list items --search web
sshr add web -u deploy --bw-key <item id>        # an SSH Key item
```

Needs the `bw` CLI unlocked, each connect reads the item. App: **Bitwarden** for the password or **Key in Bitwarden**. Without a session a password is asked by ssh, a key host stops with the error. References do not sync

## Jump hosts

```sh
sshr add 10.0.0.7 -u app -J bastion        # a saved host
sshr add 10.0.0.7 -u app -J ops@gw:2222    # or user@host:port
sshr add 10.0.0.7 -u app -J gw,bastion     # a chain
```

Saved hops log in with their own key or password (sshr runs itself as `ProxyCommand`), plain hops go to ssh as `-J`

## Keeping the session on the server

```sh
sshr add 10.0.0.7 -u app --session tmux    # or zellij
sshr connect --plain web                    # skip it once
```

Off by default, attaches to the session `sshr` or creates it, a dropped connection does not lose your work

## Port forwards

```sh
sshr forward add web db -L 5432:localhost:5432
sshr forward add web socks -D 1080
sshr tunnel web db             # only the forward, Ctrl+C closes
sshr connect -F db web         # shell with the forward, -F all for every one
```

## Reusing connections

`--reuse` or **Settings → Connection** (`"reuse": true`): sessions to one host share a connection, the second opens at once, off by default: one drop closes every session on it, and while it is up no password is asked, not on Windows. `sshr close web` ends it

## Connecting with mosh

`--mosh` or **Settings → Connection** (`"mosh": true`): survives network changes and sleep, off by default: needs mosh on both sides and open UDP 60000-61000, no forwards, no scrollback without tmux, no Windows client, falls back to ssh when mosh fails

## Is the host up

```sh
sshr ping            # exits 1 when a host is down
sshr list --ping
```

**Settings → Connection** (`"health_check": true`) shows a dot with the round trip next to each host, every 5 minutes (`"health_interval"`), off by default: sshd logs every check and fail2ban in `ddos` or `aggressive` mode may ban you, hosts behind a jump host are not checked

## Sending images to a server

```sh
sshr paste web              # clipboard image to the server, prints its path there
sshr paste -c web           # and copies that path
sshr paste -f shot.png web
```

App: **Send image** on a host, the file goes to `~/.cache/sshr/pasted/` and is removed after 15 minutes, Linux needs `wl-clipboard` or `xclip`

## Sync between devices

```sh
sshr sync init --server https://sync.example.com --name laptop
sshr sync join --server https://sync.example.com <code>   # new device, shows a fingerprint
sshr sync approve <id>                                    # after comparing fingerprints
sshr sync                                                 # pull and push
sshr sync status
sshr sync remove-device <id>
```

End to end encrypted, the server sees only ciphertext, saved passwords sync, keys kept in sshr do not, a host changed on two devices keeps both versions, the other one as `<name> (conflict ...)`, sync runs when you call it

## Sync server

```sh
go build -o sshr-sync ./cmd/sshr-sync
sshr-sync --autocert sync.example.com --listen :443 --data /var/lib/sshr-sync
sshr-sync --tls-cert cert.pem --tls-key key.pem --listen :8443 --data ./data
sshr-sync --plain-http --listen 127.0.0.1:8080 --data ./data   # behind a TLS proxy
```

## AI assistants (MCP)

```sh
claude mcp add --transport stdio sshr -- sshr mcp
claude mcp add --transport stdio sshr -- sshr mcp --allow-commands
```

Other clients: `{"mcpServers": {"sshr": {"command": "sshr", "args": ["mcp"]}}}`, tools: `list_hosts`, `upload_file`, `run_command`, running commands is off by default (`--allow-commands` or `"mcp_commands": true`), secrets never leave sshr, hosts that ask for a password cannot be used

## REST API

```sh
sshr serve                            # unix socket $XDG_RUNTIME_DIR/sshr/api.sock
sshr serve --listen 127.0.0.1:7522    # loopback port, token in ~/.sshr/api-token
curl --unix-socket "$XDG_RUNTIME_DIR/sshr/api.sock" http://x/v1/hosts
```

| Method and path | |
|----|----|
| `GET /v1/hosts`, `GET /v1/hosts/{host}` | list, one host |
| `POST /v1/hosts`, `DELETE /v1/hosts/{host}` | add, remove |
| `GET /v1/hosts/{host}/connect` | the ssh command line |
| `POST /v1/hosts/{host}/upload?ext=png` | upload the body, returns the remote path |
| `POST /v1/hosts/{host}/run` | run a command, off by default (`--allow-commands`, `"api_commands": true`) |
| `POST /v1/hosts/{host}/tunnels`, `GET /v1/tunnels`, `DELETE /v1/tunnels/{id}` | open, list, close forwards |

## Roadmap

[docs/ROADMAP.md](docs/ROADMAP.md), board: [SSHR](https://github.com/users/klovbin/projects/3)
