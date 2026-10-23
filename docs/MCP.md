# MCP server

`sshr mcp` lets an AI assistant (Claude Code, Claude Desktop, Cursor, VS Code, Codex, Windsurf and any other MCP client) see your saved hosts, put a file on a server and, if you turn it on, run commands there. It speaks MCP over stdin and stdout of a child process the client starts, nothing listens on a port.

- [Setup](#setup)
- [Tools](#tools)
- [What an assistant can and cannot do](#what-an-assistant-can-and-cannot-do)
- [Running commands](#running-commands)
- [The log of commands](#the-log-of-commands)
- [Example session](#example-session)
- [Troubleshooting](#troubleshooting)

## Setup

Every client starts the same thing: the command `sshr` with the argument `mcp`, add `--allow-commands` to let it run commands (see [Running commands](#running-commands)). A client started from the desktop may not have your shell's PATH, if it cannot find `sshr`, put the full path from `command -v sshr` (`where sshr` on Windows) in place of `sshr`.

### Claude Code

```sh
claude mcp add --transport stdio sshr -- sshr mcp                    # this project only
claude mcp add --transport stdio --scope user sshr -- sshr mcp       # every project
claude mcp add --transport stdio sshr -- sshr mcp --allow-commands   # and let it run commands
```

The server is stored in `~/.claude.json`, or in `.mcp.json` in the project root with `--scope project`, under `mcpServers`.

### Claude Desktop

Settings, Developer, Edit Config opens `claude_desktop_config.json` (`~/Library/Application Support/Claude/` on macOS, `%APPDATA%\Claude\` on Windows). Add:

```json
{
  "mcpServers": {
    "sshr": { "command": "sshr", "args": ["mcp"] }
  }
}
```

Restart Claude Desktop after saving.

### Cursor

`~/.cursor/mcp.json` for every project, `.cursor/mcp.json` in a project for that project:

```json
{
  "mcpServers": {
    "sshr": { "type": "stdio", "command": "sshr", "args": ["mcp"] }
  }
}
```

### VS Code (Copilot agent mode)

```sh
code --add-mcp '{"name":"sshr","type":"stdio","command":"sshr","args":["mcp"]}'
```

This adds it to your user profile, "MCP: Open User Configuration" opens that file. For one workspace, `.vscode/mcp.json` holds the same entry under `servers` (not `mcpServers`):

```json
{
  "servers": {
    "sshr": { "type": "stdio", "command": "sshr", "args": ["mcp"] }
  }
}
```

### Codex

```sh
codex mcp add sshr -- sshr mcp
```

or in `~/.codex/config.toml` (`.codex/config.toml` in a repository for that repository):

```toml
[mcp_servers.sshr]
command = "sshr"
args = ["mcp"]
```

### Windsurf

The "..." menu of the Cascade panel, "Open MCP config file", opens the file to edit (`mcp_config.json`), add the entry under `mcpServers`:

```json
{
  "mcpServers": {
    "sshr": { "command": "sshr", "args": ["mcp"] }
  }
}
```

### Any other client

A client that starts stdio servers needs the command `sshr` and the arguments `["mcp"]`, most of them take the `mcpServers` block above. sshr answers MCP protocol versions 2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05.

## Tools

A host is named the way `sshr connect` takes it: the exact ID, then the name, the address, an ID prefix. A name that matches several hosts is refused with the list of them and their short IDs, the assistant then asks with the ID.

### list_hosts

No arguments, read only. Returns every saved host: `name`, `id`, `address`, `user`, `port`, `auth` (how it logs in, in words), `jump`, `session`, `forwards`, `tags` and `last_connected`. No password, key or secret reference is part of it.

### upload_file

| Argument | |
|----|----|
| `host` | the host |
| `path` | absolute path of a local file |

Copies the file to `~/.cache/sshr/pasted/paste-<time>.<extension>` on the server and returns the full path there, the assistant then hands that path to a program on the server.

- a regular file of at most 100 MiB, the extension is letters and digits, up to 10, a file without one gets `.bin`
- links are resolved first, a file in a hidden folder of your home or a hidden file there (`~/.ssh`, `~/.sshr`, `~/.aws`, `~/.config` and so on) is refused, so an assistant cannot send your keys, tokens or sync state
- the file is removed on the server after 15 minutes, each upload also removes older ones in case the timer was stopped by a logout
- it goes through the host's jump hosts like a connection

### run_command

Offered only when commands are on, see [Running commands](#running-commands).

| Argument | |
|----|----|
| `host` | the host |
| `command` | a command line, run with `sh -c` on the server |
| `timeout_seconds` | 60 by default, at most 600 |

Returns the exit code, stdout and stderr, each cut at 64 KiB (`truncated` tells), a non-zero exit code is marked as an error so the assistant notices it.

- no terminal and empty stdin, interactive programs (editors, `top`, a `sudo` that asks for a password) do not work
- the server stops the command when the time is up, if it has `timeout` (coreutils or busybox), otherwise sshr drops the connection 15 s later and the command may keep running there
- at most 8 uploads and commands run at once, the others wait for a free slot, other requests are answered meanwhile

## What an assistant can and cannot do

- **Secrets stay in sshr.** No tool returns a password, a private key or a 1Password or Bitwarden reference, sshr hands a saved password to ssh itself, the same way as for `sshr connect`.
- **A host that asks for its password every time cannot be used**, there is no terminal to type it in. Save its password in sshr or log in with a key. A key with a passphrase works through an ssh agent only.
- **Commands are off by default.** Without them an assistant can read the host list and put files into `~/.cache/sshr/pasted/` on a server, which is removed after 15 minutes.
- **With commands on it can do on a server whatever your user there can**, including deleting data and stopping services. `run_command` is marked destructive, so clients ask before each call, unless you turned that off in the client.
- **Nothing listens.** The client starts `sshr mcp` as its own child process, no other program on the machine or the network can reach it.

## Running commands

```sh
sshr mcp --allow-commands    # on for this server
sshr mcp --no-commands       # off for this server, whatever the setting says
```

or, for every client at once, in `~/.sshr/settings.json`:

```json
{ "mcp_commands": true }
```

The flag wins over the setting. The client reads the tool list when it starts the server, restart the server in the client after a change.

## The log of commands

Every command is written to stderr of the server before it runs, as `sshr mcp: run on <host>: <command>`. Where the client shows it:

- **Claude Desktop:** `mcp-server-sshr.log` in `~/Library/Logs/Claude` (macOS) or `%APPDATA%\Claude\logs` (Windows), `mcp.log` there has connection errors
- **Cursor:** the Output panel (Ctrl+Shift+U, Cmd+Shift+U on macOS), "MCP Logs"
- **VS Code:** MCP: List Servers, sshr, Show Output
- **Claude Code, Codex, Windsurf:** their documentation does not say where stderr of a server goes, for a record that does not depend on the client, start sshr through a shell that keeps it:

```json
{ "command": "sh", "args": ["-c", "exec sshr mcp --allow-commands 2>>\"$HOME/.sshr/mcp.log\""] }
```

## Example session

You ask: "the nginx on web returns 502, look at what is wrong and send it this config to compare".

1. `list_hosts` finds `web` (`deploy@10.0.0.5`, key file).
2. `run_command` on `web`: `tail -n 50 /var/log/nginx/error.log`, the client asks you first, you allow it, the result shows `connect() failed (111: Connection refused) while connecting to upstream`.
3. `upload_file` of `/home/you/nginx.conf` to `web` returns `/home/deploy/.cache/sshr/pasted/paste-1760870000000.conf`.
4. `run_command`: `diff /etc/nginx/nginx.conf /home/deploy/.cache/sshr/pasted/paste-1760870000000.conf`, the assistant explains the difference and what to change.

Without commands on, only steps 1 and 3 are possible, the assistant can still tell you which commands to run yourself.

## Troubleshooting

**The client does not see the server or says it failed to start.** Run `sshr mcp` in a terminal, it should wait silently for input (Ctrl+C to quit). If the command is not found there, sshr is not installed in PATH, if it works there but not in the client, put the full path to `sshr` in the client's config. Check the JSON for a missing comma and the key name (`servers` in VS Code's own file, `mcpServers` elsewhere).

**`run_command` is missing.** Commands are off, see [Running commands](#running-commands), and restart the server in the client.

**A host is missing from the list.** The server reads the hosts of the user who started the client, `~/.sshr/vault/hosts`. A host added on another machine arrives with `sshr sync pull`, `sshr list` shows what the server sees.

**"this host asks for its password on every connect".** Save the password in sshr or switch the host to a key, see above.

**"Host key verification failed".** There is no terminal to confirm a new host key, connect once with `sshr connect <host>` and accept it.

**"the command did not finish in 60 s".** Give a bigger `timeout_seconds` (up to 600). A longer job belongs in `nohup` or a tmux session on the server, and the assistant checks on it with later calls.

**"matches several hosts".** The assistant has to use the ID from the message, or rename one of the hosts.
