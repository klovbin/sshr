<p align="center"><img src="assets/icons/sshr-logo.png" width="128" height="128" alt="sshr logo"></p>

# sshr

sshr keeps your SSH servers in one list and connects to them with one command, from a desktop app or the terminal, on Linux, macOS and Windows, it runs on top of the system `ssh`, stores hosts on your machine and needs nothing on the servers

- [passwords](docs/USAGE.md#passwords) encrypted with your system keychain, [keys stored in sshr](docs/USAGE.md#keys-stored-in-sshr), keys from [ssh agents](docs/USAGE.md#keys-from-an-ssh-agent), [1Password](docs/USAGE.md#passwords-and-keys-in-1password) and [Bitwarden](docs/USAGE.md#passwords-and-keys-in-bitwarden)
- [jump hosts](docs/USAGE.md#jump-hosts), [tmux or zellij sessions](docs/USAGE.md#keeping-the-session-on-the-server), [port forwards](docs/USAGE.md#port-forwards), [shared connections](docs/USAGE.md#reusing-connections), [mosh](docs/USAGE.md#connecting-with-mosh)
- [tags and search](docs/USAGE.md#tags-and-search), [health check](docs/USAGE.md#health-check), [import](docs/USAGE.md#importing-sshconfig) and [export](docs/USAGE.md#exporting-to-sshconfig) of `~/.ssh/config`
- [copy files](docs/USAGE.md#copying-files), [run a command on many hosts](docs/USAGE.md#running-a-command-on-many-hosts), [send clipboard images](docs/USAGE.md#sending-images-to-a-server)
- [end to end encrypted sync](docs/USAGE.md#sync-between-devices) through [your own server](docs/USAGE.md#sync-server)
- [MCP server](docs/MCP.md) for AI assistants and a local [REST API](docs/USAGE.md#rest-api)

Anything that costs something (an extra connection, editing your files, commands from AI) is off until you turn it on

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/klovbin/sshr/main/install.sh | sh
```

Linux and macOS, into `~/.local/bin` without root, [install options](docs/USAGE.md#install), Windows: `go build -o sshr.exe ./cmd/sshr`, packages for AUR, Homebrew, Scoop and nixpkgs are [planned](docs/PACKAGING.md)

## Quick start

```sh
sshr add 10.0.0.7 -u deploy -n web    # asks how to log in
sshr import                            # or bring hosts from ~/.ssh/config
sshr list
sshr connect web
sshr                                   # the desktop app
```

## Documentation

- [Usage](docs/USAGE.md): every command, option and what it costs
- [Features](docs/FEATURES.md): what each feature is for
- [Security](docs/SECURITY.md): how passwords, keys and sync data are protected
- [Architecture](docs/ARCHITECTURE.md): packages, data on disk, flows, decisions
- [Packaging](docs/PACKAGING.md): how sshr gets into AUR, Homebrew, Scoop and nixpkgs
- [Roadmap](docs/ROADMAP.md) and the [project board](https://github.com/users/klovbin/projects/3)
- [Why it is built this way](docs/WHY.md) (Russian)

## Contributing

Bugs and ideas go to [issues](https://github.com/klovbin/sshr/issues), build with `go build ./cmd/sshr` (the GUI needs cgo, `-tags nocgo` builds the CLI only), test with `go test -tags nocgo` on every package but `internal/ui`, CI runs the tests and a real sshd on Linux, macOS and Windows

## Support

<p align="center">
  <a href="https://www.buymeacoffee.com/klovbin">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me a Coffee" height="41" width="174">
  </a>
</p>

## License

Copyright (c) 2026 klovbin

sshr is released under the [MIT License](LICENSE). You are free to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software, provided the copyright notice and permission notice are included in all copies or substantial portions of the software. The software is provided "as is", without warranty of any kind.
