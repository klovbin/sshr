# Using sshr

Every command, option and its cost, the overview is in the [README](../README.md), what each feature is for in [FEATURES.md](FEATURES.md), how secrets are protected in [SECURITY.md](SECURITY.md)

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/klovbin/sshr/main/install.sh | sh   # or sh install.sh in a checkout
```

- Linux and macOS, into `~/.local/bin` (`--prefix <dir>` or `SSHR_PREFIX`), no root
- takes the release binary `sshr_<os>_<arch>` only when it matches `sha256sums.txt`, otherwise builds from source: Go 1.21+ (go fetches the toolchain from `go.mod`), the GUI also needs a C compiler and on Linux Wayland/X11 and Vulkan headers, without them the CLI is built and the script says so, `--cli-only` skips the GUI
- adds one line marked `# added by the sshr installer` to your shell startup file when the folder is not in `PATH` (`--no-modify-path` skips it), runs `sshr desktop-entry` when the GUI is installed
- writes Tab completion for bash and fish when they are installed (`--no-completion` skips it), for zsh it prints the line to add to `~/.zshrc`
- `--uninstall` removes the binary, the menu entry, the completion files and that line, hosts in `~/.sshr` stay
- Windows: `go build -o sshr.exe ./cmd/sshr`, packages for AUR, Homebrew, Scoop and nixpkgs are planned ([#17](https://github.com/klovbin/sshr/issues/17))

**Icon and menu:** `sshr desktop-entry` (`--remove` undoes it) writes `sshr.desktop` and icons to `~/.local/share` on Linux and `~/Applications/sshr.app` on macOS (signed ad hoc, it holds a copy of sshr because the Dock shows a bundle icon only for a program inside it, run it again after an update, `install.sh` does), on Windows the icon is a resource of `sshr.exe`, icons are built into the binary, logo files are in `assets/icons`, `go generate ./cmd/sshr` rebuilds the Windows resources

## Basic commands

```sh
sshr                                     # the app
sshr add 10.0.0.7 -u app -n web          # asks how to log in
sshr add 10.0.0.7 -u app -k ~/.ssh/id_ed25519 -p 2222 -t prod
sshr list                                # NAME HOST USER PORT AUTH TAGS ID
sshr list --recent                       # last connected first, LAST says how long ago
sshr list --json                         # the same as JSON, also ping --json and run --json
sshr connect web                         # by name or ID
sshr connect deploy@10.0.0.7:2222        # not saved: connects once, then offers to save
sshr show web                            # the host and the exact ssh command connect runs
sshr key new                             # ed25519 key in ~/.ssh/sshr_ed25519, never overwrites
sshr key install web --use               # put the public key on web and log in with it from then on
sshr rm web
sshr help                                # one line per command
sshr help add                            # the options of one command
sshr completion fish | source            # Tab completion, also bash and zsh
```

## Passwords

```sh
sshr add db.example.com -u admin --no-key         # saved, encrypted
sshr add db.example.com -u admin --ask-password   # nothing saved, ssh asks every time
```

- a saved password is sealed with XChaCha20-Poly1305 in the host file, the key is 32 random bytes in the system keychain (Secret Service, macOS Keychain, Windows Credential Manager), never on disk
- it reaches ssh through sshr's own askpass over a one-shot unix socket, never through a file, argv or the environment, it is tried once (`NumberOfPasswordPrompts=1`, three failures are enough for fail2ban), only a password prompt gets it, host key questions and one-time codes go to the terminal
- `sshr list` and the host form never decrypt, an empty password field keeps the saved one
- no keychain (a server without a desktop, a keyring nobody unlocks within 5 s): a saved password cannot be added, ask mode and keys still work
- a reset keychain or `~/.sshr` copied to another machine makes the password unreadable and sshr asks to save it again, plain `"password"` fields from older versions are encrypted on the next save

### Without a system keychain

```sh
sshr vault passphrase    # move the vault key into a file under a passphrase
sshr vault status        # keychain or passphrase
sshr vault keychain      # back to the system keychain, the file is removed
```

- the vault key that seals saved passwords and stored keys lives in the system keychain, on a server or a machine without one `passphrase` wraps it into `~/.sshr/vault/vault-key.json` with Argon2id, the key stays the same, so everything saved before still opens
- off by default: the passphrase is asked once per run, a forgotten one loses every saved secret, the file can be attacked offline with a weak passphrase (8 characters at least)
- it is asked on the terminal, or from the program in `SSHR_ASKPASS`, `sshr mcp` never asks on its terminal, `SSHR_VAULT=keychain|passphrase` picks the mode for one run
- the keys of the sync device move along into `~/.sshr/vault/secrets.json`, each sealed with the vault key, so a machine without a keychain syncs too, `keychain` moves them back

## Keys stored in sshr

```sh
sshr add web -u deploy --key-stdin < key   # a passphrase is asked once
```

- the key is sealed like a password, no file in `~/.ssh`, a passphrase key is stored without the passphrase, the vault encryption replaces it
- on connect sshr serves it from an agent inside its own process (a unix socket in a 0700 folder, a named pipe on Windows), only in memory, ssh gets `-i <id>.pub -o IdentitiesOnly=yes` and offers only this key, agent forwarding is off for the host
- the public half is kept next to the host file, the form and `sshr add` show its fingerprint
- keys do not sync, other devices see the fingerprint and are asked to paste the key there

## Keys from an ssh agent

```sh
sshr add web -u deploy --agent                              # SSH_AUTH_SOCK
sshr add web -u deploy --agent 1password --agent-key work   # the 1Password SSH agent
sshr add web -u deploy --agent /path/agent.sock --agent-key SHA256:...
```

- `1password` is `~/.1password/agent.sock` on Linux, `~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock` on macOS, `\\.\pipe\openssh-ssh-agent` on Windows, any other socket works too (Bitwarden, KeePassXC, hardware key agents)
- `--agent-key` picks one key by fingerprint, comment or a unique part and ssh offers only it, servers stop after about six tries, with several keys and no `--agent-key` `sshr add` asks

## Passwords and keys in 1Password

```sh
sshr add web -u deploy --op-password op://Private/web/password
sshr add web -u deploy --no-key --store 1password --op-vault Servers   # creates a Login item "sshr web"
sshr add web -u deploy --op-key "op://Private/web key/private key"
```

- needs the `op` CLI signed in, each connect reads the item (a locked app asks for a fingerprint), only the reference is kept
- a new item gets the password as a JSON template on stdin, not in arguments, the vault comes from `--op-vault` or `"op_vault"`
- `op` missing or locked: ssh asks for a password on the terminal, a key host stops with the error, a new password for a linked host is changed in 1Password, an existing private key is imported in the 1Password app first, then linked

## Passwords and keys in Bitwarden

```sh
export BW_SESSION="$(bw unlock --raw)"
sshr add web -u deploy --bw-password <item id>   # bw list items --search web
sshr add web -u deploy --bw-key <item id>        # an SSH Key item
```

- needs the `bw` CLI unlocked (`BW_SESSION`), each connect reads the item, sshr never sees the master password, a name works only when it finds one item
- no session: ssh asks for a password, a key host stops with the error, items are created in Bitwarden itself
- 1Password and Bitwarden references stay on the device where they were set and never sync

## Jump hosts

```sh
sshr add 10.0.0.7 -u app -J bastion        # a saved host
sshr add 10.0.0.7 -u app -J ops@gw:2222    # or user@host:port
sshr add 10.0.0.7 -u app -J gw,bastion     # a chain, gw first
```

- plain hops go to ssh as `-J`, a saved hop makes ssh run sshr as `ProxyCommand`, so each hop logs in with its own saved key or password (`-J` would use only your ssh config)
- a saved jump host may have its own jump, a loop stops after 8 hops, mosh is not used through a jump host

### Gateway when the host does not answer

```sh
sshr add 10.0.0.7 -u app --gateway bastion   # direct when it answers, else through bastion
sshr gateway db bastion                      # set it on a saved host
sshr gateway db --off                        # connect directly again
```

- connect, run, send, get, tunnel and paste first check the host directly, a TCP connect and the SSH banner, up to 3 s each, and go through the gateway only when it does not answer, `connect` prints `via bastion (no answer directly)`
- off by default: a host that is down directly costs that wait on every connect, a host with `-J` always goes through its jump hosts and cannot have a gateway
- `sshr ping` says `connect goes through bastion` next to a host that is down directly, the ssh config export writes the direct way, plain ssh has no fallback
- the gateway syncs like jump hosts, a device with an older sshr drops it when it saves that host until versioned records land ([#97](https://github.com/klovbin/sshr/issues/97))

## Keeping the session on the server

```sh
sshr add 10.0.0.7 -u app --session tmux    # or zellij
sshr connect --plain web                    # a plain shell this once
```

Off by default, runs `tmux new-session -A -s sshr` (or `zellij attach --create sshr`) under `sh`, so any login shell works and a dropped connection keeps your work, without the tool on the server you get a plain shell

## Port forwards

```sh
sshr forward add web db -L 5432:localhost:5432    # local 5432 to the server's 5432
sshr forward add web app -R 8080:localhost:3000   # the server's 8080 to your 3000
sshr forward add web socks -D 1080                # SOCKS proxy
sshr forward web                                  # list, sshr forward rm web socks
sshr tunnel web db                                # only the forward, Ctrl+C closes, all when no names
sshr connect -F db web                            # a shell with the forward, -F all for every one
```

The spec is what ssh takes after `-L`, `-R`, `-D`, checked on save, `tunnel` uses `ExitOnForwardFailure` so a busy port fails at once, forwards go through jump hosts, mosh carries none

## Reusing connections

`--reuse` / `--no-reuse` per command or `"reuse": true` (**Settings → Connection**): sessions to one host share a connection (`ControlMaster`, kept 10 minutes), the second opens in about 0.1 s instead of 0.65 s, off by default: one drop closes every session on it, while it is up no password is asked and anyone with your account can use its socket (kept in a 0700 folder), Windows OpenSSH has no `ControlMaster`, `sshr close web` ends it, a `ControlMaster` in your ssh config wins

## Connecting with mosh

`--mosh` / `--ssh` per call or `"mosh": true`: survives network changes and sleep, echoes typing at once, off by default: needs `mosh` here and `mosh-server` plus open UDP 60000-61000 there, no port or agent forwarding, no scrollback without tmux, no terminal images, no Windows client, falls back to ssh when mosh is missing, fails within 20 s, or an ssh option has spaces

## Health check

```sh
sshr ping              # every host, exits 1 when one is down
sshr list --ping       # STATUS column, --no-ping skips it
sshr ping --keys web   # also the server key: known, unknown or changed against ~/.ssh/known_hosts
```

`"health_check": true` (**Settings → Connection**) shows a dot with the round trip next to each host, every 5 minutes (`"health_interval"`, 60 s at least) and after a change, off by default: each check is a TCP connect and the SSH banner without login, but sshd logs it and fail2ban in `ddos` or `aggressive` mode counts it, up means the banner came within 3 s, orange is an open port that is not ssh, hosts behind a jump host show `?`

## Tags and search

```sh
sshr add 10.0.0.7 -u app -n web -t prod,web
sshr tag web +eu -web          # add and remove, sshr tag web shows them
sshr list prod                 # name, address, user or tag contains "prod"
sshr list '#prod' db           # exact tag plus "db" anywhere, tag:prod works too
```

Lower case letters, digits, `.`, `_`, `-`, up to 20 per host, the app has a **Tags** field and a search box with the same rules, tags sync

## Copying files

```sh
sshr send web report.pdf logs/ --to /srv/in   # to the home folder without --to
sshr get web /var/log/nginx --to ./logs       # to the current folder without --to
```

scp with the host's key, password, jump hosts and shared connection, folders copy whole, `--legacy` (scp -O) for servers without an SFTP subsystem

## Running a command on many hosts

```sh
sshr run -t prod -- uptime                  # every host with all the tags
sshr run web db --timeout 30 -- 'df -h /'   # by name
```

8 at a time (`-j`), each host's output as one block, exit 1 when one fails, stopped on the server after `--timeout` (60 s) where `timeout` exists, hosts that ask for a password are skipped

## Sending images to a server

```sh
sshr paste web              # clipboard image to the server, prints the remote path
sshr paste -c web           # and copies that path, replacing the image
sshr paste -f shot.png web  # a file instead of the clipboard
```

- a screenshot pasted into a remote session is a path on your disk, sshr uploads the image and gives the path on the server, in the app **Send image** puts that path in the clipboard
- the file goes to `~/.cache/sshr/pasted/` and is removed after 15 minutes, the server needs only `sh`, the app has no terminal, so a host that asks for its password is refused there
- clipboard tools: `wl-paste`/`wl-copy` (wl-clipboard) or `xclip` on Linux, `osascript`/`pbcopy` on macOS, PowerShell/`clip` on Windows

## Importing ~/.ssh/config

```sh
sshr import --dry-run
sshr import
```

- in the app: **Settings → Import**, `import-ssh-config` and `export-ssh-config` are older names of `import` and `export` and keep working
- every `Host` of `~/.ssh/config` and its `Include`s, resolved with `ssh -G`, so `Match`, `Host *` and defaults apply as in ssh, nothing goes over the network, `Match exec` runs what you wrote
- carries `HostName`, `User`, `Port`, `IdentityFile`, `IdentityAgent` (the 1Password socket becomes `1password`), `ProxyJump` and forwards as `l1`, `r1`, `d1`
- patterns are skipped, a `ProxyCommand` host keeps its alias as the address, hosts sshr already has are skipped, so a second run adds only new ones

## Exporting to ~/.ssh/config

```sh
sshr export               # print
sshr export --install     # write ~/.sshr/ssh_config, include it, keep it current
sshr export --uninstall
```

- in the app: **Settings → Import → Export**, off by default, it edits your file
- `Include ~/.sshr/ssh_config` goes first in `~/.ssh/config`, every change of the hosts rewrites the export, so `ssh my-box`, `scp` and editors find them (`my box` becomes `my-box`)
- exported: address, user, port, key file, agent and chosen key, `ProxyJump`, not exported: passwords and keys kept in sshr or a password manager, forwards, sessions
- names your config already has are skipped, values that could add ssh options skip the host, a linked `~/.ssh/config` is not edited, sshr prints the line instead

## Sync between devices

```sh
sshr sync init --server https://sync.example.com --name laptop   # first device
sshr sync join --server https://sync.example.com <code>          # new device, shows its fingerprint
sshr sync approve <id>                                           # on a device already in, after comparing fingerprints
sshr sync                                                        # pull, then push
sshr sync status                                                 # devices and a state fingerprint
sshr sync remove-device <id>                                     # rotates the vault key
sshr sync leave                                                  # stop syncing here, the hosts stay
```

- end to end encrypted: per-device keys in the keychain (Ed25519, ML-KEM-768 + X25519), hosts encrypted with a shared vault key, signed and chained manifests, the server stores only ciphertext and cannot add a device or forge history
- saved passwords sync inside the encryption, keys kept in sshr and password manager references do not, key file paths sync, the files do not
- a host changed on two devices keeps both, the other one as `<name> (conflict <device> <date>)`, a host removed on one device and changed on another comes back with the change, the log says so
- a host whose saved password does not open here, or one this sshr cannot read, is left out and named, the other hosts still sync, `sshr sync` then ends with "N hosts left out" and exit code 1
- `leave` first delivers a vault key this device changed and has not handed to the others yet, `--force` leaves without it, then the others pair again
- an S3 bucket instead of sshr-sync: `sshr sync init --backend s3 --endpoint https://<account>.r2.cloudflarestorage.com --bucket sshr --key-id <id> --name laptop`, `--prefix` keeps several accounts in one bucket, `--region` defaults to `auto`, the secret key comes from `SSHR_S3_SECRET` or a prompt and is kept in the keychain, `sshr sync invite` prints the join flags without it, pass the secret to the new device yourself, the endpoint has to be HTTPS without a user or password in it (plain HTTP only to a loopback address such as 127.0.0.1, also when the sync state is edited), setup checks that the bucket refuses a second create of one name, see SECURITY.md for what a shared bucket key allows, after `remove-device` make a new bucket key, delete the old one and run `sshr sync store-key --key-id <new id>` on every device that stays, it keeps the bucket and checks that the new key reads the account and the vault key of this device before it saves it, the key needs read, write, list and delete on the whole prefix of the account
- a WebDAV folder instead: `sshr sync init --backend webdav --url https://cloud.example/remote.php/dav/files/<user>/sshr --user <user> --name laptop`, the password (in Nextcloud an app password) comes from `SSHR_WEBDAV_PASSWORD` or a prompt and is kept in the keychain, setup checks that the server refuses a second create of one name, works with Nextcloud and ownCloud 10 with file locking on (the default), Apache mod_dav passes the check but two devices pushing at the same moment can lose a change there, OCIS, nginx, rclone, Caddy and dufs are refused, a redirect is an error, give the address the server redirects to, after `remove-device` change the password and run `sshr sync store-key` on every device that stays, with the same `--user <name>` on each if the user changes too
- a Supabase project instead: `sshr sync supabase-sql > setup.sql` prints the SQL and once the sshr key of the account (keep it in a password manager, every device needs it), run the SQL in the SQL editor of the project, then `sshr sync init --backend supabase --url https://<ref>.supabase.co --key <publishable key> --name laptop`, the sshr key comes from `SSHR_SUPABASE_KEY` or a prompt and is kept in the keychain, a secret (`sb_secret_`) or service_role key is refused, `sshr sync invite` prints the join flags without the sshr key, a free project sleeps after a week without requests and sshr says so, resume it in the dashboard, after `remove-device` run `sshr sync supabase-sql --replace`, run its SQL, then `sshr sync store-key` with the new key on every device that stays, change or unset `SSHR_SUPABASE_KEY` wherever it holds the old key, sshr takes the variable before it asks, the test of the SQL on a real database needs `postgresql_17` and `postgrest` (`go test -run TestReal ./internal/supastore/`)
- limits: sync runs when you call it, the server sees the host count, push times, addresses and device names and can hold back changes, a new device trusts the first state it sees (`--accept-reset` after a real server restore), compare the `sshr sync status` fingerprints to be sure two devices see the same history, a removed device keeps what it downloaded, the server and a bucket keep the last 1000 changes, a device further behind has to leave and join again

## Sync server

```sh
go build -o sshr-sync ./cmd/sshr-sync
sshr-sync --autocert sync.example.com --listen :443 --data /var/lib/sshr-sync   # Let's Encrypt
sshr-sync --tls-cert cert.pem --tls-key key.pem --listen :8443 --data ./data
sshr-sync --plain-http --listen 127.0.0.1:8080 --data ./data                     # behind a TLS proxy
sshr-sync --plain-http --trust-proxy --listen 127.0.0.1:8080 --data ./data       # the proxy sets X-Forwarded-For
```

TLS 1.3 only, plain HTTP only on loopback, one token per device (only its SHA-256 is stored), 10 new accounts or joins an hour per address, behind a proxy every client has the proxy's address unless `--trust-proxy` takes the last `X-Forwarded-For` entry of requests from this machine (off by default, the proxy must set that header), pushes are compare-and-swap so two devices cannot overwrite each other, unused blobs go after a day, an account holds at most 20000 blobs and 256 MiB (507 after that), one server per data folder

`GET /v1/health` answers 200 while the data folder can be written and 503 when it cannot, for a monitor, it needs no token and tells nothing about accounts

Backups: everything is in the data folder, `accounts/<id>/devices.json` (devices and token hashes), `blobs/` (encrypted hosts), `manifests/` (the signed history) and `envelopes/` (the vault key for each device), plus the TLS cache of `--autocert`. It holds no plaintext and no key that opens the hosts, a copy can sit anywhere. Stop sshr-sync or take a filesystem snapshot for the copy, a copy made file by file while devices push can hold a manifest whose blobs are missing. Restore only the newest copy: a device refuses a history older than the one it already saw, so after an old copy is restored the devices stop syncing until the account is set up again, the hosts themselves stay on every device

## Extensions

```sh
sshr ext community on                                        # turns the catalog on after a notice, off by default
sshr ext search remmina                                      # lists the community catalog
sshr ext install remmina                                     # from the catalog, at the commit it names
sshr ext install https://github.com/someone/sshr-hello.git   # shows what it is and asks
sshr ext install ./my-extension --yes                        # a folder, no question, for scripts
sshr hello a b                                               # runs the extension called hello
sshr ext import remmina                                      # an extension that reads another tool's hosts
sshr ext list
sshr ext remove hello
```

The catalog is off until `sshr ext community on` (`sshr ext community off` turns it off again, installed extensions stay). It is a JSON file at `ext_catalog` in `~/.sshr/settings.json`, by default the community one, `extensions/catalog.json` in the sshr repository (`https://raw.githubusercontent.com/klovbin/sshr/main/extensions/catalog.json`). To add your extension, open a pull request that adds an entry there, the test of the repository checks its shape, nobody reviews its code, each entry has a name, an https git address, a full commit hash, a description, an author and kinds, an entry of a wrong shape or a name listed twice is left out with a warning, a folder here with the same name as a catalog entry is installed as a folder. A company can serve its own file over HTTPS, the format is `{"version":1,"extensions":[{"name":"hello","url":"https://…/hello.git","commit":"<40 hex>","description":"…","author":"…","kinds":["command"]}]}`. Nobody reviews the code of catalog extensions, an entry is checked for its shape only.

A working one to copy from is `examples/extensions/hello` (`sshr ext install ./examples/extensions/hello`). Importers that come with sshr are in `extensions/`, `extensions/remmina` reads the SSH profiles of Remmina (`~/.local/share/remmina/*.remmina`, or the folders you pass), Remmina keeps passwords in the keyring, so a host comes without its password and logs in as ssh does by default, install it from a clone with `sshr ext install ./extensions/remmina`. `extensions/putty` reads the saved sessions of PuTTY on Linux and macOS where PuTTY keeps them (`~/.config/putty/sessions` or `~/.putty/sessions`, `$PUTTYSESSIONS` and `$PUTTYDIR` count), an SSH proxy of a session becomes a jump host, a `.ppk` key is left out with the `puttygen` command that converts it, PuTTY saves no passwords. An extension is a folder with a manifest `sshr-ext.json` and the program it runs:

```json
{
  "protocol": 1,
  "name": "hello",
  "version": "0.1.0",
  "description": "says hello to a host",
  "command": { "default": ["./hello.sh"], "windows": ["hello.exe"] },
  "kinds": ["command"]
}
```

- `name` is lower case letters, digits and `-`, it is the word after `sshr`, an extension cannot take the name of a command of sshr
- `command` is a list of arguments per system (`linux`, `darwin`, `windows`, `default` for the rest), the first one is a file of the folder, no shell is involved, the arguments you type after the name are added
- the program gets the terminal of the user and its exit code is the exit code of sshr
- sshr passes `SSHR_EXT_PROTOCOL` (1), `SSHR_EXT_KIND` (`command`), `SSHR_EXT_DIR` (its folder), `SSHR_EXT_DATA` (a folder it may write to, `~/.sshr/extension-data/<name>`, it stays when the extension is removed) and `SSHR_BIN` (the sshr binary), `"$SSHR_BIN" list --json` gives it the hosts
- the files of the folder are pinned, so write state, caches and logs to `SSHR_EXT_DATA` and never into the folder, a file that appears there stops the extension, `PYTHONDONTWRITEBYTECODE=1` is set for Python ones
- passwords, keys, secret references and the variables of ssh askpass, Bitwarden and 1Password are never in its environment
- `"kinds": ["import"]` makes an importer, `sshr ext import <name> [args]` runs it with `SSHR_EXT_KIND=import` and the terminal for input and messages, reads what it prints on stdout (8 MiB at most, 5000 hosts) and saves the hosts:

  ```json
  {"hosts": [{"key": "putty:web", "name": "web", "host": "10.0.0.5", "port": 22, "user": "deploy",
              "key_file": "/home/me/.ssh/id_ed25519", "jump": "gw", "session": "tmux",
              "tags": ["prod"], "forwards": ["db -L 5432:localhost:5432"]}]}
  ```

  `key` names the host in its source and is required, the same key gives the same host on the next import, which is then skipped as already imported, so nothing you edited since is overwritten, only these fields are read, a password, a key or a secret reference an importer prints is dropped with a warning, a host that fails the checks of sshr is reported and the others are saved
- `sshr ext install` pins every file of the folder, changing one (a `git pull` in the folder, an edit) stops the extension until you install it again, how that is checked and what it does not cover is in [SECURITY.md](SECURITY.md#extensions)

## AI assistants (MCP)

```sh
claude mcp add --transport stdio sshr -- sshr mcp                    # Claude Code
claude mcp add --transport stdio sshr -- sshr mcp --allow-commands   # and let it run commands
```

Other clients: `{"mcpServers": {"sshr": {"command": "sshr", "args": ["mcp"]}}}`

- `list_hosts` (read only), `upload_file` (to `~/.cache/sshr/pasted/`, removed after 15 minutes, hidden files and folders of your home such as `~/.ssh` and `~/.sshr` are refused), `run_command` (stdout and stderr up to 64 KiB each, exit code, `timeout_seconds` 60 by default, 600 at most)
- `run_command` is off by default (`--allow-commands` or `"mcp_commands": true`), it is marked destructive so clients ask before each call
- secrets never leave sshr, hosts that ask for a password cannot be used, nothing listens (stdin and stdout of a child process), every command is logged to stderr

- `--confirm-commands` (or `"confirm_commands": true`) asks before each `run_command` through a question the client shows, it runs only after a yes, a client that cannot show questions gets commands refused, `sshr serve` refuses commands while it is set
- `sshr commands only` limits `run_command` to the hosts of `sshr commands allow <host>` (`"commands_listed_only": true`, `--listed-hosts-only` for one run), a host that points elsewhere since it was allowed is refused until it is allowed again, `sshr commands all` and `--all-hosts` go back to every host
- `--audit` (or `"audit_log": true`) keeps `~/.sshr/audit.jsonl`: a JSON line at the start and at the end of each upload and command, with the client, the host and the exit code, a command as its length, first word and a keyed hash (`"audit_commands": "full"` keeps it whole), the file moves to `audit.jsonl.1` at `audit_max_mb` (10) and five old files stay, an action whose start cannot be written is refused

Setup for each client, every tool with its limits, the log and troubleshooting: [MCP.md](MCP.md)

## REST API

```sh
sshr serve                            # unix socket $XDG_RUNTIME_DIR/sshr/api.sock (or ~/.sshr/cm/api.sock)
sshr serve --listen 127.0.0.1:7522    # loopback only, token from ~/.sshr/api-token
curl --unix-socket "$XDG_RUNTIME_DIR/sshr/api.sock" http://x/v1/hosts
curl -H "Authorization: Bearer $(cat ~/.sshr/api-token)" http://127.0.0.1:7522/v1/hosts
```

| Method and path | |
|----|----|
| `GET /v1/hosts`, `GET /v1/hosts/{host}` | list, one host by name, address or ID |
| `POST /v1/hosts` | add: `name`, `host`, `user`, `port`, `key`, `agent`, `agent_key`, `ask_password`, `jump`, `session`, `forwards`, `tags` |
| `DELETE /v1/hosts/{host}` | remove |
| `GET /v1/hosts/{host}/connect` | the ssh command line as `{"argv": [...]}` |
| `POST /v1/hosts/{host}/upload?ext=png` | the body is the file, returns its remote path, removed after 15 minutes |
| `POST /v1/hosts/{host}/run` | `{"command", "timeout_seconds"}`, off by default (`--allow-commands`, `"api_commands": true`) |
| `POST /v1/hosts/{host}/tunnels`, `GET /v1/tunnels`, `DELETE /v1/tunnels/{id}` | open saved forwards, list, close |

`--audit` writes host changes, uploads, runs and tunnels to the same `~/.sshr/audit.jsonl` as `sshr mcp`, the client is the uid on the socket or the address on a port

Never listens on the network (`127.0.0.1`, `::1`, `localhost` only), the socket is 0600 in a 0700 folder, a port needs the token, requests with an `Origin` (web pages) or a non-loopback `Host` (DNS rebinding) are refused, passwords, keys and references are never returned or accepted
