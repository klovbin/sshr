# Architecture

How sshr is built, which package may use which, where data lives and how the main flows run. Statements about today's code are checked against it, the package rules are enforced by `internal/archtest`, what is not there yet is marked as planned. The reasons behind the decisions are in [WHY.md](WHY.md) (Russian), the security model in [SECURITY.md](SECURITY.md).

## Constraints

- local first: hosts live on your machine, no account, no cloud, sync goes through a server you run and that cannot read them
- system `ssh` does the connecting, sshr builds its command line and supplies logins, so known_hosts, ssh_config, FIDO keys and agents behave as in plain ssh
- no background service: nothing runs unless you start it, the CLI commands are short, the app, `sshr serve` and `sshr mcp` live as long as you keep them open
- secrets are sealed at rest and never leave the machine in the clear, anything that costs something is off by default
- two people work on the code: the desktop app (`internal/ui`) is one person's, everything else the other's, they meet only at the `internal/app` API

## Layers

```
          cmd/sshr (CLI, composition root)                cmd/sshr-sync
         /       |       |        |          \                  |
  internal/ui   api     mcp   syncclient   desktop, clip    syncserver
         \       |       |      /     \                         |
          internal/app (core)          syncproto <--------------+
```

| Package | Does | May import (sshr packages) |
|----|----|----|
| `internal/app` | the core: hosts and their store, secrets, ssh command lines, ssh config import and export, health, settings | nothing |
| `internal/syncproto` | wire types and limits of sync, shared by client and server | nothing |
| `internal/syncclient` | device keys, pull, push, conflicts, key rotation | `app`, `syncproto` |
| `internal/syncserver` | the HTTP sync server, stores ciphertext only | `syncproto` |
| `internal/api` | local REST API over the core | `app` |
| `internal/mcp` | MCP server over the core | `app` |
| `internal/ext` | extensions: manifest, the installed ones, running one with a clean environment | `app` |
| `internal/ui` | the Gio desktop app | `app`, `clip`, `i18n`, `assets` |
| `internal/desktop` | menu entry, icons, app bundle | `assets` |
| `internal/clip`, `internal/i18n`, `assets` | clipboard, translations, embedded icons | nothing |
| `cmd/sshr` | CLI commands, wires the front ends together | `app`, `api`, `mcp`, `ext`, `syncclient`, `ui`, `desktop`, `clip`, `assets` |
| `cmd/sshr-sync` | starts the sync server | `app` (only for its file lock, planned to move), `syncserver` |

Rules that follow:

- the core knows no front end, a feature written in `app` is available to the CLI, the app, MCP and the API at once
- front ends do not import each other, the app does not call the CLI and the API does not call MCP
- `internal/syncserver` never imports the core or the client, it cannot decrypt what it stores by construction
- `internal/ui` changes only through its owner, a need of the app becomes a function in `app` and an issue for the GUI

## Inside the core

`internal/app` is one package grouped by file:

| Area | Files |
|----|----|
| hosts and their store | `store.go` (Host, Store, Add, Update, Import, FromOtherDevice, ListAll, Find), `tags.go`, `summary.go`, `version.go` |
| secrets | `vault.go` (vault key in the keychain, seal and unseal), `vaultkey.go` (keys kept in sshr, served through a private agent), `sshauth.go` (AttachAuth, askpass socket for saved passwords), `onepassword.go`, `bitwarden.go`, `manager.go`, `agent.go`, `keyfile.go` |
| ssh command lines | `upload.go` (SSHArgs, the base builder, and uploads), `jump.go` (ConnectArgs, JumpArgs, ProxyHop), `reuse.go`, `session.go`, `forward.go`, `copy.go`, `remote.go` |
| reachability | `health.go`, a TCP connect and the SSH banner in process, no ssh |
| ssh config | `sshconfig.go` (import through `ssh -G`), `sshexport.go` (export, the Include line in `~/.ssh/config`, `WriteFileAtomic`) |
| settings | `settings.go` |
| platform | `lock_*.go`, `tty_*.go`, `agentsock_*.go` |

The core builds the ssh, scp and remote command lines and runs `op`, `bw`, `scp` and remote commands. Starting the interactive session is not in the core yet: `cmd/sshr` adds `-t`, the session command and the mosh wrapper, `internal/api` adds the tunnel options itself (planned change 2).

## Processes

- each process reads what it needs from disk, the disk is the only truth, nothing is shared in memory between processes
- the app, `serve` and `mcp` can run for hours next to CLI commands and a sync, they must read hosts again instead of trusting a list they loaded earlier, the vault key is cached for the life of a process
- a keychain call runs with a 5 s timeout, MCP runs at most 8 commands or uploads at once, the REST API has no such limit
- every change of hosts (add, update, import, remove, duplicate, last connect, the ssh config export) runs under the lock file `~/.sshr/vault/hosts/.lock`, the sync takes it for each host from reading the local version to writing the remote one, a process that waits more than 30 s gives up with the pid of the holder, the lock belongs to the open file, so two goroutines of the app exclude each other too
- a sync run (init, join, approve, pull, push, remove-device, leave) holds `~/.sshr/sync/run.lock` and reads the state again under it, a second run stops at once with "another sshr process is running a sync", the run lock is taken before the host lock and never after it
- a lock does not help when the copy is read long before the save, so every host file carries `rev`, a save counter of this machine, `Store.Update` refuses a copy whose `rev` is not the saved one with `ErrChanged` (#107), the CLI passes the host it read and says "run the command again", a connect does not raise `rev`, so it never refuses an open form, the sync payload leaves `rev` out
- settings loaded long before a save (the app loads them once at start) remember what was read, `SaveSettings` reads the file again under `~/.sshr/settings.json.lock` and writes only the fields its holder changed since (#106), so two writers of different settings both keep their change, a `Settings` value built from scratch is written whole

## Data on disk

| Path | Holds | Written by |
|----|----|----|
| `~/.sshr/vault/hosts/<id>.json` | one host per file, 0600, `rev` counts its saves on this machine, passwords sealed as v2 (bound to the destination), keys sealed, a password from an old version stays in clear in `password` while the keychain cannot be used | `Store.save` through `WriteFileAtomic` |
| `~/.sshr/vault/hosts/<id>.pub` | public half of a key kept in sshr, for `-i` with an agent | `writePub`, plain `os.WriteFile` |
| `~/.sshr/vault/.lock` | lock for creating the vault key | `VaultKey` |
| `~/.sshr/vault/hosts/.lock` | lock for changing hosts, holds the pid of the holder | `Store.locked` |
| keychain, service `sshr`, entry `vault-key` | the vault key that seals the secrets | `VaultKey` |
| 1Password items | a password saved with `--store 1password` | `opStorePassword` |
| `~/.sshr/settings.json` | settings, fields it does not know are lost on save | `SaveSettings` through `WriteFileAtomic` |
| `~/.sshr/settings.json.lock` | lock for saving settings, holds the pid of the holder | `SaveSettings` |
| `~/.sshr/ssh_config` | the export | `refreshSSHConfig` through `WriteFileAtomic` |
| `~/.ssh/config` | the user's own file, sshr adds or removes one Include line, a link is left alone | `editUserConfig` through `WriteFileAtomic`, its mode kept |
| `~/.sshr/sync/run.lock` | lock of a sync run, holds the pid of the holder | `syncclient.run` |
| `~/.sshr/sync/state.json` | the sync state: chain head, trusted devices, entry states, skipped entries, a pending key rotation | `syncclient.save` through `WriteFileAtomic` |
| keychain, service `sshr`, entries `sync-device`, `sync-key-<epoch>`, `sync-key-pending` | device seed, vault keys per epoch, a key not delivered yet | `syncclient` |
| `~/.sshr/extensions/<name>/` | an installed extension: its files and `sshr-ext.json` by the author | `sshr ext install`, `ext.Registry.Install` |
| `~/.sshr/extension-data/<name>/` | what an extension writes, state and caches, it stays when the extension is removed | the extension itself, `SSHR_EXT_DATA` |
| `~/.sshr/extensions/.pins.json` | the pin of each installed extension: source, commit, hash of every file, outside the folders so a folder cannot bring its own, an extension folder without a pin is not trusted | `ext.Registry.Install` under `~/.sshr/extensions/.lock` |
| `~/.sshr/api-token` | token of the REST API on a TCP port | `apiToken` through `WriteFileAtomic` |
| `$XDG_RUNTIME_DIR/sshr` or `~/.sshr/cm` | ControlMaster sockets, askpass and agent sockets, `api.sock` | ssh, `sshauth`, `vaultkey`, `sshr serve` |
| sync server data folder | accounts, devices, envelopes, manifests, blobs, all ciphertext but the device list | `syncserver`, its own copy of the atomic write |

`WriteFileAtomic` writes a temp file of its own, syncs it, renames it over the target and syncs the folder, a crash leaves the old file or the new one.

## Flows

**Connect.** `Store.Find` (exact ID, then name, address, ID prefix, an ambiguous query is refused) → `ConnectArgs` (key, agent, jump hosts as `-J` or a quoted ProxyCommand through `sshr __proxy`, reuse) → `cmd/sshr` adds forwards, `-t` and the session, or wraps it in mosh with a fallback to ssh → `AttachAuth` (`Unlock` opens the sealed password or asks 1Password or Bitwarden, on failure the terminal prompt stays, an askpass socket gives the password to the right token once, a key kept in sshr goes through a private agent) → `ssh` runs as a child, `forwardSignals` passes signals on, its exit code is sshr's.

**Run an extension.** a word that is no case of the command switch → `ext.Registry.Find` (the name is checked first, so it cannot leave `~/.sshr/extensions`) → `Verify` (hash of every file against the pin, a mismatch or no pin stops here) → `Command` (the program of the folder by its full path, no PATH, no shell, the environment of the caller without secrets plus `SSHR_EXT_*` and `SSHR_BIN`) → the child gets the terminal, `forwardSignals` passes signals on, its exit code is sshr's. **Install.** `Prepare` (folder, or a shallow https or ssh clone, copied without `.git`, plain files only) → the manifest, the command and the hash are shown → a yes → `Install` (under a lock of the extensions folder) builds the folder beside the old one, checks the copy against the hash, swaps it in and writes the pin.

**Import with an extension.** `ext.Registry.Find` → `Verify` → `Command` with kind import → `Collect` reads at most 8 MiB from its stdout while input and errors stay on the terminal → `ParseImport` keeps the fields of `ExtHost` and warns about the rest → `HostID` (hash of extension name and key) → `Store.Import` under the host lock, a host that is already there is skipped.

**Sync pull.** finish a key delivery left from before → fetch every manifest after the last counter → verify each (counter, previous hash, signature of a trusted device, the MAC only on the newest) → apply the newest one entry by entry: download, read the local host again, decide by Lamport stamp and device, keep the losing side of a conflict as a copy, skip a host this version cannot take or a local file that does not load → finish a key delivery → save the state. A pull that fails puts the chain back and keeps the entry state of hosts already applied.

**Sync push.** pull first when the account has manifests → build a plan from the pulled state → seal changed hosts → write a manifest with If-Match on the counter → on 412 pull and plan again, at most 5 times. Removing a device revokes its token, commits the manifest with a new epoch while the key waits as `key-pending`, then delivers the envelopes, an interrupted delivery resumes on the next sync.

**MCP and REST.** both call the core functions the CLI uses, neither returns or accepts secrets, running commands is off by default, errors are returned to the client as their text.

## Platforms

| | Linux | macOS | Windows |
|----|----|----|----|
| shared connections (ControlMaster) | yes | yes | no, OpenSSH for Windows has none |
| mosh | yes | yes | no |
| agent sockets | unix socket | unix socket | named pipe, `//./pipe/...` for ssh |
| socket paths | under the 108 byte limit, `ControlDir` checks | under 104 bytes | not used |
| GUI build | needs cgo, CI builds it on macOS and Windows | cgo | Go only |
| CI | tests and a real sshd | tests, a real sshd, the app bundle | tests |

`go build -tags nocgo` builds the CLI without the app on any of them.

## Decisions

| Question | Decision | Instead of |
|----|----|----|
| storage | one JSON file per host, a cross-process lock for the concurrency (planned change 1) | SQLite: a broken file costs one host, sync entries map to files |
| connecting | system ssh as a child process | an SSH library: known_hosts, config, FIDO, agents and fixes come with OpenSSH, an embedded transport only for phones |
| processes | no background service | a daemon: nothing needs to stay up, `serve` and `mcp` run on demand |
| core boundary | concrete functions of `app`, one interface where the core calls out to secrets (planned change 4), tests use fake binaries on PATH instead of a process interface | a facade with interfaces for every front end |
| packages | few packages, `app` split only once its seams are stable | many small packages early |
| settings | JSON | TOML: one format, a handful of fields |
| conflicts | keep both, the later change keeps the name | last writer wins per field: host, user and jump must never be picked silently |
| extensions | executables with a fixed protocol, installed with a pinned hash (#105) | Go plugins or WASM |
| updates | GitHub releases with a pinned signing key | the sync server: anyone can run one |

## Rules for new code

- a feature goes into `app` first, front ends only parse input and print output
- every host from another device enters through `Store.Import`, which runs `FromOtherDevice` and `cleanHost`: a field that names a local secret (an item, a socket, a file) is reset in `FromOtherDevice`, a field that reaches a command line gets a validator in `cleanHost` and a check again where the line is built
- `payloadOf` strips fields from what syncs, everything else syncs, a new field that must stay on this machine has to be added there
- files are written with `app.WriteFileAtomic`, never `os.WriteFile` over the target
- secrets never reach logs, errors or output, `Host` must not be printed with `%v`, its `json:"-"` fields would show (nothing enforces this yet)
- a feature with a cost is off by default, with a setting, a flag and a fallback
- tests use fake `ssh`, `op` and `bw` on PATH and a local sync server, never real hosts, `.github/e2e.sh` checks against a real sshd

## Planned changes

In this order, each one its own issue and commits:

1. (#95) done: a lock around every change of hosts and one over a whole sync run, see Processes, what it cannot cover is fixed by #106 and #107
2. (#96) move starting a session (`cmdConnect`, `runMosh`, `cmdProxy`, `forwardSignals`, the tunnel options in `api`) into `app`, so the app can connect (#90) and the API stops repeating it
3. (#97) a versioned host record on disk and a sync payload that keeps fields it does not know, before any release, so an older device does not erase what a newer one wrote
4. (#98) a secrets provider type: keychain, 1Password, Bitwarden and a passphrase fallback for machines without a keychain, `cleanHost` stops calling `op` and `bw`, clear-text passwords of old files are sealed once the keychain works
5. (#99) move `LockFile`, `WriteFileAtomic` into a small leaf package, so `cmd/sshr-sync` and `syncserver` stop linking or copying the core, `.pub` files through it too
6. (#100) rules as tests: no `os/exec` in `ui`, `mcp`, `syncserver`, Gio only in `ui`, a test that every `Host` field is classified as synced, stripped or reset, a redacting format for `Host`, CODEOWNERS for `internal/ui`
7. (#101) an append-only audit log of MCP and REST actions, a per-host opt-in for commands from assistants, the API token on the unix socket too
8. (#102) done: `scripts/release.sh` and `.github/workflows/release.yml` build the six CLI files on a tag, checksums and a build attestation, the GUI is not in them, packages (#17) are next
9. (#103) split `app` by its areas once 2 and 4 have settled the seams
