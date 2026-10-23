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
          cmd/sshr (CLI, composition root)                  cmd/sshr-sync
         /       |       |        |          \                    |
  internal/ui   api     mcp   syncclient   desktop, clip      syncserver
         \       |       |        |   \                           |
          internal/app (runs ssh,  |    syncproto <---------------+
          op, bw, the keychain)    |
                  \                |
       hosts, health, vault, settings, record, fileio (no programs)
```

| Package | Does | May import (sshr packages) |
|----|----|----|
| `internal/audit` | the audit log of MCP and REST actions | `fileio` |
| `internal/pwmgr` | 1Password and Bitwarden through their CLIs: read a password or a key, create a login item, the accounts op knows | `settings` |
| `internal/health` | whether a host answers (TCP and the SSH banner) and the key it shows against known_hosts, no login, no program | `hosts` |
| `internal/hosts` | hosts and their files: Host, the store with its lock, checks, records across versions, forwards, tags, summaries, runs no program, the steps that do come as hooks from `app` | `fileio`, `record`, `vault` |
| `internal/vault` | the vault key in a keychain or under a passphrase, seals bound to a host and field, named secrets of the sync device, runs no program, the system keychain and the prompt are set by `app` | `fileio`, `settings` |
| `internal/settings` | `~/.sshr/settings.json`: load, save of the changed fields only, the command list, never synced | `fileio`, `record` |
| `internal/record` | keeps files readable across versions: unknown keys kept and written back, the `version` of a file | nothing |
| `internal/fileio` | atomic file writes, file locks between processes, a read that waits out a Windows rename, imports nothing of sshr | nothing |
| `internal/app` | the core: the Store facade over package hosts, ssh command lines, password managers, ssh config import and export | `fileio`, `record`, `settings`, `vault`, `hosts`, `health`, `pwmgr` |
| `internal/syncproto` | wire types and limits of sync, shared by client and server | nothing |
| `internal/s3store` | a sync account in an S3 bucket (AWS S3, R2, MinIO) through the AWS SDK, the create of a manifest is PutObject with If-None-Match: * | `syncclient` |
| `internal/syncclient` | device keys, pull, push, conflicts, key rotation, runs no program | `fileio`, `record`, `vault`, `hosts`, `syncproto` |
| `internal/syncserver` | the HTTP sync server, stores ciphertext only | `syncproto`, `fileio` |
| `internal/api` | local REST API over the core | `app`, `audit` |
| `internal/mcp` | MCP server over the core | `app`, `audit` |
| `internal/ext` | extensions: manifest, the installed ones, running one with a clean environment | `app` |
| `internal/ui` | the Gio desktop app | `app`, `clip`, `i18n`, `assets` |
| `internal/desktop` | menu entry, icons, app bundle | `assets`, `fileio` |
| `internal/clip`, `internal/i18n`, `assets` | clipboard, translations, embedded icons | nothing |
| `cmd/sshr` | CLI commands, wires the front ends together | `app`, `audit`, `api`, `mcp`, `ext`, `syncclient`, `ui`, `desktop`, `clip`, `assets` |
| `cmd/sshr-sync` | starts the sync server | `fileio`, `syncserver` |

Rules that follow:

- the core knows no front end, a feature written in `app` is available to the CLI, the app, MCP and the API at once
- front ends do not import each other, the app does not call the CLI and the API does not call MCP
- `internal/syncserver` never imports the core or the client, it cannot decrypt what it stores by construction
- `internal/ui` changes only through its owner (`.github/CODEOWNERS` asks for their review), a need of the app becomes a function in `app` and an issue for the GUI
- the GUI, `mcp`, the sync packages, `fileio`, `i18n` and `assets` do not import `os/exec`, only the core, the CLI, `api`, `ext`, `desktop` and `clip` start programs
- `syncproto`, `syncclient`, `s3store`, `fileio`, `record`, `settings`, `vault`, `hosts`, `health`, `i18n`, `syncserver` and `cmd/sshr-sync` do not reach `os/exec` through any import, the packages a phone build links stay free of it, what runs ssh stays in `app`
- Gio is imported only by `internal/ui`
- `internal/archtest` checks all of these

## Inside the core

`internal/app` is one package grouped by file:

| Area | Files |
|----|----|
| hosts and their store | package `hosts` (`store.go`, `host.go`, `record.go`, `forward.go`, `tags.go`, `summary.go`, `redact.go`, `hop.go`, `refs.go`, `pub.go`), in app `storefacade.go` (Store, its hooks, DefaultStore, Unlock) and `hosts.go` (aliases), `version.go` |
| secrets | `vault.go` (the system keychain and the passphrase prompt handed to package vault, wrappers), `keychain_system.go`, `prompt.go`, `vaultkey.go` (keys kept in sshr, served through a private agent), `sshauth.go` (AttachAuth, askpass socket for saved passwords), `pwmgr.go` and `opstore.go` over package pwmgr, `agent.go` |
| ssh command lines | `upload.go` (SSHArgs, the base builder, and uploads), `jump.go` (ConnectArgs, JumpArgs, ProxyHop), `reuse.go`, `session.go`, `forward.go`, `copy.go`, `remote.go` |
| reachability | package `health`, a TCP connect and the SSH banner in process, no ssh, `hostkey.go` there reads the host key |
| ssh config | `sshconfig.go` (import through `ssh -G`), `sshexport.go` (export, the Include line in `~/.ssh/config`) |
| settings | `settings.go` (aliases of package settings) |
| platform | `files.go` (`WriteFileAtomic`, `LockFile`, `WaitLock` over `fileio`), `tty_*.go`, `agentsock_*.go` |

The core builds the ssh, scp and remote command lines and runs `op`, `bw`, `scp` and remote commands. A session is planned in the core too: `Store.PlanSession` (`internal/app/launch.go`) turns a host and `LaunchOptions` (forwards, mosh, plain, tunnel, batch) into the ssh or mosh command line on a copy of the host, with the route through a gateway, the notes for the user and the ssh fallback of a mosh plan, `SessionPlan.Command` attaches the host's secrets. `sshr connect`, `sshr tunnel` and the tunnels of the REST API use it. Running the process, waiting for it, forwarding signals and printing stay with the caller, a GUI must not forward a terminal's signals.

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
| `~/.sshr/vault/hosts/<id>.pub` | public half of a key kept in sshr, for `-i` with an agent | `writePub` through `WriteFileAtomic` |
| `~/.sshr/vault/.lock` | lock for creating the vault key | `VaultKey` |
| `~/.sshr/vault/hosts/.lock` | lock for changing hosts, holds the pid of the holder | `Store.locked` |
| keychain, service `sshr`, entry `vault-key` | the vault key that seals the secrets | `VaultKey` |
| 1Password items | a password saved with `--store 1password` | `opStorePassword` |
| `~/.sshr/settings.json` | settings, fields a newer sshr wrote are kept, never synced | `settings.Save` through `fileio.WriteFile` |
| `~/.sshr/settings.json.lock` | lock for saving settings, holds the pid of the holder | `settings.Save` |
| `~/.sshr/ssh_config` | the export | `refreshSSHConfig` through `WriteFileAtomic` |
| `~/.ssh/config` | the user's own file, sshr adds or removes one Include line, a link is left alone | `editUserConfig` through `WriteFileAtomic`, its mode kept |
| `~/.sshr/sync/run.lock` | lock of a sync run, holds the pid of the holder | `syncclient.run` |
| `~/.sshr/sync/state.json` | the sync state: chain head, trusted devices, entry states, skipped entries, a pending key rotation | `syncclient.save` through `WriteFileAtomic` |
| keychain, service `sshr`, entries `sync-device`, `sync-key-<epoch>`, `sync-key-pending` | device seed, vault keys per epoch, a key not delivered yet | `syncclient` |
| `~/.sshr/extensions/<name>/` | an installed extension: its files and `sshr-ext.json` by the author | `sshr ext install`, `ext.Registry.Install` |
| `~/.sshr/extension-data/<name>/` | what an extension writes, state and caches, it stays when the extension is removed | the extension itself, `SSHR_EXT_DATA` |
| `~/.sshr/extensions/.pins.json` | the pin of each installed extension: source, commit, hash of every file, outside the folders so a folder cannot bring its own, an extension folder without a pin is not trusted | `ext.Registry.Install` under `~/.sshr/extensions/.lock` |
| `~/.sshr/audit.jsonl`, `audit.jsonl.1` to `.5` | the audit log of `sshr mcp` and `sshr serve` with `--audit`, one JSON line per start and end of an action, 0600, moves to `.1` at `audit_max_mb`, the older ones move on and five stay | `audit.Log.Begin` appending under `audit.jsonl.lock` |
| `~/.sshr/audit.key` | key of the command hashes in the audit log | `audit.Open` |
| `~/.sshr/api-token` | token of the REST API on a TCP port | `apiToken` through `WriteFileAtomic` |
| `$XDG_RUNTIME_DIR/sshr` or `~/.sshr/cm` | ControlMaster sockets, askpass and agent sockets, `api.sock` | ssh, `sshauth`, `vaultkey`, `sshr serve` |
| sync server data folder | accounts, devices, envelopes, manifests, blobs, all ciphertext but the device list | `syncserver`, its own copy of the atomic write |

`WriteFileAtomic` writes a temp file of its own, syncs it, renames it over the target and syncs the folder, a crash leaves the old file or the new one. Windows refuses that rename, and a read during it, while another process has the file open, so there the rename and `ReadFileShared` (settings, hosts, the export, the sync state, the extension pins) retry for up to 500 ms.

## Flows

**Connect.** `Store.Find` (exact ID, then name, address, ID prefix, an ambiguous query is refused) → `ConnectArgs` (key, agent, jump hosts as `-J` or a quoted ProxyCommand through `sshr __proxy`, reuse) → `cmd/sshr` adds forwards, `-t` and the session, or wraps it in mosh with a fallback to ssh → `AttachAuth` (`Unlock` opens the sealed password or asks 1Password or Bitwarden, on failure the terminal prompt stays, an askpass socket gives the password to the right token once, a key kept in sshr goes through a private agent) → `ssh` runs as a child, `forwardSignals` passes signals on, its exit code is sshr's.

**Run an extension.** a word that is no case of the command switch → `ext.Registry.Find` (the name is checked first, so it cannot leave `~/.sshr/extensions`) → `Verify` (hash of every file against the pin, a mismatch or no pin stops here) → `Command` (the program of the folder by its full path, no PATH, no shell, the environment of the caller without secrets plus `SSHR_EXT_*` and `SSHR_BIN`) → the child gets the terminal, `forwardSignals` passes signals on, its exit code is sshr's. **Install.** `Prepare` (folder, or a shallow https or ssh clone, copied without `.git`, plain files only) → the manifest, the command and the hash are shown → a yes → `Install` (under a lock of the extensions folder) builds the folder beside the old one, checks the copy against the hash, swaps it in and writes the pin.

**Import with an extension.** `ext.Registry.Find` → `Verify` → `Command` with kind import → `Collect` reads at most 8 MiB from its stdout while input and errors stay on the terminal → `ParseImport` keeps the fields of `ExtHost` and warns about the rest → `HostID` (hash of extension name and key) → `Store.Import` under the host lock, a host that is already there is skipped.

**Sync pull.** finish a key delivery left from before → fetch every manifest after the last counter → verify each (counter, previous hash, signature of a trusted device, the MAC only on the newest) → apply the newest one entry by entry: download, read the local host again, decide by Lamport stamp and device, keep the losing side of a conflict as a copy, skip a host this version cannot take or a local file that does not load → finish a key delivery → save the state. A pull that fails puts the chain back and keeps the entry state of hosts already applied.

**Sync push.** pull first when the account has manifests → build a plan from the pulled state → seal changed hosts → write a manifest with If-Match on the counter → on a lost race (`ErrCASLost`, 412 from sshr-sync) pull and plan again, at most 5 times. Removing a device revokes its token, commits the manifest with a new epoch while the key waits as `key-pending`, then delivers the envelopes, an interrupted delivery resumes on the next sync.

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
| storage | one JSON file per host, a cross-process lock for the concurrency (#95) | SQLite: a broken file costs one host, sync entries map to files |
| connecting | system ssh as a child process | an SSH library: known_hosts, config, FIDO, agents and fixes come with OpenSSH, an embedded transport only for phones |
| processes | no background service | a daemon: nothing needs to stay up, `serve` and `mcp` run on demand |
| core boundary | concrete functions of `app`, one interface where the core calls out to secrets (`Keychain`, #98), tests use fake binaries on PATH instead of a process interface, the app still gets `app.Host` with its in-memory secret fields, API and MCP get `HostSummary` | a facade with interfaces for every front end |
| packages | few packages, `app` split only once its seams are stable | many small packages early |
| settings | JSON with a version and unknown keys kept (#97) | TOML: one format, a handful of fields, the version rules apply either way |
| conflicts | keep both, the later change keeps the name, a three-way merge of changes to different fields is deferred (#152) | last writer wins per field: host, user and jump must never be picked silently |
| extensions | executables with a fixed protocol, installed with a pinned hash (#105) | Go plugins or WASM |
| updates | GitHub releases with a pinned signing key, planned (#146), today a build attestation | the sync server: anyone can run one |

## Rules for new code

- a feature goes into `app` first, front ends only parse input and print output
- `cleanHost` only checks and normalizes fields and runs no program, reading a public key from 1Password or Bitwarden happens in `fillKeyPub` when a host is added or edited
- every host from another device enters through `Store.Import`, which runs `FromOtherDevice` and `cleanHost`: a field that names a local secret (an item, a socket, a file) is reset in `FromOtherDevice`, a field that reaches a command line gets a validator in `cleanHost` and a check again where the line is built
- `payloadOf` strips fields from what syncs, everything else syncs, a new field that must stay on this machine has to be added there, the unknown keys of a host travel too (`app.HostPayloadJSON`), except those named `local_...`, which a newer sshr uses for what stays on one machine, a payload with no unknown keys (from an older sshr) leaves the keys here as they are
- files are written with `app.WriteFileAtomic`, never `os.WriteFile` over the target
- a host file is read with `decodeHost` and written with `encodeHost` (`internal/hosts/record.go`): a key this build does not know, a field a newer sshr wrote, is kept in `Host.extra` and written back, `Update` carries it from the file, a form that never drew the field cannot erase it, a file whose `version` is newer than `hostFormat` is read and connected to, every write of it fails with `ErrNewerFormat`, removing it works
- secrets never reach logs, errors or output, `Host.String` and `GoString` (`redact.go`) replace passwords, keys, sealed values, secret references and unknown fields, so `%v`, `%+v`, `%#v` and `%s` of a host are safe, a test checks every verb
- a feature with a cost is off by default, with a setting, a flag and a fallback
- tests use fake `ssh`, `op` and `bw` on PATH and a local sync server, never real hosts, `.github/e2e.sh` checks against a real sshd
- one host that does not unseal or decode is skipped with a note, it never stops a sync or an import of the others (#144, #136)

## Planned changes

In this order, each one its own issue and commits, the order was checked against the research and the code (`opus-check-2026-10-23`), the bugs #144 and #145 come before 3:

1. (#95) done: a lock around every change of hosts and one over a whole sync run, see Processes, what it cannot cover is fixed by #106 and #107
2. (#96) done: `PlanSession` and `SessionPlan.Command` in `app` plan connect, tunnel and the API tunnels, the CLI keeps running the process and its signals, the app can build its connect on it (#90)
3. (#97) done: host files, settings.json, the sync state and the extension pins keep the keys a newer sshr wrote and carry a `version`, a file newer than the binary is read and not written (`ErrNewerFormat`), host payloads carry the unknown keys except `local_...`, a host of a newer format is not pushed by a build that cannot write it and is skipped where it arrives and cannot be written, manifests of older formats are read, a golden test pins the payload bytes of today's hosts and a table classifies every `Host` field
4. (#98) done: every secret goes through the `Keychain` interface (system keychain, or `secrets.json` under the passphrase vault), keychain states are told apart (missing, locked, timeout with a quiet minute), `sshr vault passphrase` keeps the vault key in a file wrapped with Argon2id for machines without a keychain, stored keys are sealed for their destination like passwords, `cleanHost` runs no program, clear passwords of old files are sealed at start, a `Store.Vault` injected instead of the package-level keychain is left for the phone build
5. (#99) done: `internal/fileio` holds the atomic write, the file lock and the shared read, `cmd/sshr-sync` no longer links the core, `syncserver` and `desktop` dropped their copies of the write, `.pub` files are written through it too
6. (#100) done: archtest checks `os/exec` (direct and through any import for the phone packages) and Gio, `TestHostFieldsAreClassified` classes every `Host` field, `Host.String` redacts secrets, CODEOWNERS asks the GUI owner, a key file and an agent of a host that moved on another device are dropped (#195)
7. (#101) done: `internal/audit` keeps the audit log of MCP and REST actions, `sshr commands` limits commands to allowed hosts bound to where they point, `confirm_commands` asks through MCP elicitation and fails closed, remote output and synced host text reach the model as data (`internal/mcp/text.go`), the API socket refuses peers of another user instead of asking for a token (the same user can read the token anyway), REST runs at most 8 uploads and commands at once
8. (#102) done in part: `scripts/release.sh` and `.github/workflows/release.yml` build the six CLI files on a tag, checksums and a build attestation, the GUI is not in them, the pinned-key signature and its check in install.sh are #146, packages (#17) are next
9. (#103) done: `record`, `settings`, `vault`, `hosts`, `health` and `pwmgr` left `app`, the sync client builds on `hosts` and `vault`, everything a phone build needs reaches no `os/exec` and archtest checks it, `app` keeps the Store facade with its hooks, the system keychain, the passphrase prompt, the ssh runner and the ssh config import and export, splitting those last two is #222
10. (#128) in progress: every request of the sync client goes through `syncclient.Backend` (`backend.go`), `httpBackend` is sshr-sync, its answers become `StatusError` with the text of the server and the meanings `ErrNotFound`, `ErrCASLost`, `ErrStaleEpoch`, `ErrPending`, `testdata/http-trace.golden` pins the requests, `ObjectBackend` (`objectstore.go`) runs an account in any store with a create-only-if-absent write (manifests/<counter>, one envelope per epoch, blobs/<hash>, devices/<id>), tested over a store in memory, `internal/s3store` is the S3 store, next the CLI and a backend in the sync state, then Supabase, 1Password and a synced folder, after 3 so every backend carries the versioned payload, a backend must offer compare and swap on the manifest or the protocol must say how a fork merges, a fork looks like a rollback today and stops sync
