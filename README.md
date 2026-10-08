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

- Sync with key services (1Password, Bitwarden, ssh-agent)
- Password handling (local secrets, then encrypted vault)
- GitHub / git vault sync across machines
- Connect / session workflows on top of system SSH
