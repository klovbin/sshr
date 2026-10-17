# Roadmap

What is done, what is being worked on and what comes next, each item links its issue, the board is [SSHR](https://github.com/users/klovbin/projects/3), reasons for each decision are in [WHY.md](WHY.md) (Russian), how to use each feature is in [USAGE.md](USAGE.md), how secrets are protected in [SECURITY.md](SECURITY.md)

## Done

Connecting

- connect and session workflows on top of system ssh ([#7](https://github.com/klovbin/sshr/issues/7)): jump hosts with saved hops and chains ([#8](https://github.com/klovbin/sshr/issues/8)), attach to tmux or zellij ([#9](https://github.com/klovbin/sshr/issues/9)), named port forwards and `sshr tunnel` ([#10](https://github.com/klovbin/sshr/issues/10)), connection reuse with `ControlMaster`, off by default ([#11](https://github.com/klovbin/sshr/issues/11)), mosh, off by default
- clipboard images to a server with `sshr paste` and from the app
- whether a host answers: `sshr ping`, `sshr list --ping`, a dot in the app, off by default
- tags and search in the CLI and the app ([#31](https://github.com/klovbin/sshr/issues/31))
- one command on many hosts by tag or name, `sshr run` ([#33](https://github.com/klovbin/sshr/issues/33))
- copying files and folders, `sshr send` and `sshr get` ([#32](https://github.com/klovbin/sshr/issues/32))

Passwords and keys

- saved passwords sealed with a key from the system keychain, or asked every time ([#6](https://github.com/klovbin/sshr/issues/6))
- private keys kept inside sshr, passphrase keys included ([#12](https://github.com/klovbin/sshr/issues/12))
- passwords and keys read from 1Password, new 1Password items from the app ([#13](https://github.com/klovbin/sshr/issues/13))
- keys from an ssh agent, the 1Password SSH agent included ([#5](https://github.com/klovbin/sshr/issues/5))
- passwords and keys read from Bitwarden with `bw` ([#20](https://github.com/klovbin/sshr/issues/20))

Moving hosts in and out

- import from `~/.ssh/config` through `ssh -G`
- export to `~/.ssh/config` with an `Include` line, kept up to date, off by default
- sync between devices through our own server `sshr-sync`, end to end encrypted, conflicts keep both sides ([#1](https://github.com/klovbin/sshr/issues/1)), 1Password references stay on the device where they were set ([#30](https://github.com/klovbin/sshr/issues/30))

For other programs

- MCP server for AI assistants, `sshr mcp`, commands off by default ([#4](https://github.com/klovbin/sshr/issues/4))
- local REST API, `sshr serve` ([#3](https://github.com/klovbin/sshr/issues/3))

Installing

- `install.sh` for Linux and macOS with checksum check and PATH setup ([#2](https://github.com/klovbin/sshr/issues/2))
- the logo as the app icon: `.exe` resources on Windows, a menu entry on Linux, `~/Applications/sshr.app` on macOS, `sshr desktop-entry`
- CI on Linux, macOS and Windows: tests, CLI run, GUI build, the macOS bundle checked

Fixed bugs: [#14](https://github.com/klovbin/sshr/issues/14), [#15](https://github.com/klovbin/sshr/issues/15), [#16](https://github.com/klovbin/sshr/issues/16), [#18](https://github.com/klovbin/sshr/issues/18), [#19](https://github.com/klovbin/sshr/issues/19), [#21](https://github.com/klovbin/sshr/issues/21), [#22](https://github.com/klovbin/sshr/issues/22), [#23](https://github.com/klovbin/sshr/issues/23), [#24](https://github.com/klovbin/sshr/issues/24), [#30](https://github.com/klovbin/sshr/issues/30)

## Next

Needed before a release

1. Check the GUI on real Windows and macOS: window, icon, askpass, Keychain prompt ([#26](https://github.com/klovbin/sshr/issues/26))
2. Choose a license, packages cannot ship without one ([#27](https://github.com/klovbin/sshr/issues/27))
3. Packages for AUR, Homebrew, Scoop and nixpkgs, release binaries with `sha256sums.txt` for `install.sh` ([#17](https://github.com/klovbin/sshr/issues/17))

Features

4. Drag and drop files onto a host in the app ([#32](https://github.com/klovbin/sshr/issues/32))
5. Fall back to a gateway when the direct connection fails ([#28](https://github.com/klovbin/sshr/issues/28))
6. Local commands before and after connect, their fields go on the #30 list ([#29](https://github.com/klovbin/sshr/issues/29))
7. Import from PuTTY, MobaXterm, Remmina, Termius, Royal TS, through the #30 list ([#34](https://github.com/klovbin/sshr/issues/34))

Later

8. sshr on iOS and Android, ssh in process, keys in the phone's keystore, joins sync like any device ([#25](https://github.com/klovbin/sshr/issues/25))
9. Sync: automatic background sync, a paper recovery key, pairing by QR code
10. Sync without a server: device to device over the local network or the user's own WireGuard tunnel, TLS 1.3 with device keys pinned at pairing
11. Optional hardware keys (YubiKey, FIDO2 `ed25519-sk`), not required

## Not planned

- Eternal Terminal, another server daemon for what tmux and mosh already cover
- autossh, it is meant for permanent tunnels, not interactive work
