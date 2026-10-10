# sshr

## About

sshr is a desktop SSH hosts manager that keeps your server list local and under your control. It runs as a native Gio UI on your machine, stores hosts as JSON in a local vault (`~/.sshr/vault`), and is built to grow into CLI commands and optional git-based sync across devices — without requiring an agent or special setup on remote systems.

It currently supports:

- Adding and listing SSH hosts (name, host/IP, user, port)
- CLI commands: `list`, `add`, `rm`, `connect`, `help`
- Private key support (`-k` flag or interactive selection)
- Auto-discovery of SSH keys in `~/.ssh/`
- Interactive authentication method prompt when adding hosts
- Local vault storage per host file (0600 permissions)
- Settings with interface language (Russian / English)
- Resizable sidebar layout and icon navigation

Planned:

- Cross-platform installer with OS auto-detection (Linux/macOS/Windows) and automatic PATH setup
- REST API for external integrations and automation
- MCP server for AI assistant access to hosts and connections
- Sync with key services (1Password, Bitwarden, ssh-agent)
- Password handling (local secrets, then encrypted vault)
- GitHub / git vault sync across machines
- Connect / session workflows on top of system SSH

Future ideas:

- Zero-knowledge sync with device-bound keys ([#10](https://github.com/klovbin/sshr/issues/10)) — the sync backend stores only ciphertext; each device keeps its own key pair (TPM where available) and the vault key is encrypted to every device, so there is no master password to brute-force; new devices are approved from an existing one by fingerprint / QR; paper recovery key; SSH private keys never leave their device
- Optional hardware keys (YubiKey / FIDO2 `ed25519-sk`) — not required, buying a dedicated device just for sshr is a big ask
