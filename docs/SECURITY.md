# How sshr protects hosts and secrets

What happens to passwords, keys and synced data, [USAGE.md](USAGE.md) says how to use each feature, [WHY.md](WHY.md) says why it was built this way (Russian)

## Saved passwords and keys

- a saved password or a key kept in sshr is sealed in the host file with XChaCha20-Poly1305, the host ID and field name as associated data, so a value copied to another host or field does not open
- the vault key is 32 random bytes in the system keychain (Secret Service, macOS Keychain, Windows Credential Manager), never on disk, created once under a file lock so two processes cannot make two keys
- every keychain call has a 5 s limit, a locked keyring that nobody answers does not hang sshr, with no keychain a saved password cannot be added, ask mode and key files keep working
- `sshr list` and the host form never decrypt, an empty password field keeps the saved one
- a reset keychain or `~/.sshr` copied to another machine makes saved secrets unreadable, sshr asks to save them again
- a key with a passphrase is opened once when added and stored without it, the vault encryption takes its place

## How a password reaches ssh

- ssh runs sshr itself as `SSH_ASKPASS`, the helper takes the password from a unix socket in a 0700 directory that answers one client with the right token and closes, the password is never in a file, an environment variable or a command line
- only a password prompt gets it, the host key question, key passphrases and one-time codes are asked on the terminal
- a saved password is tried once (`NumberOfPasswordPrompts=1`), retries only feed fail2ban

## How a key from sshr or 1Password reaches ssh

- sshr serves the key from an ssh agent inside its own process for as long as ssh runs, on a unix socket in the 0700 control directory (a named pipe on Windows), the private key is only in memory
- ssh gets `-i <id>.pub -o IdentitiesOnly=yes -o IdentityAgent=SSH_AUTH_SOCK -o ForwardAgent=no`, it offers only this key and the server cannot reach the agent
- 1Password items are read with `op read` on every connect, a new item gets the password as a JSON template on stdin, not in arguments
- Bitwarden items are read with `bw get password` and `bw get item` (the key is in the item's `sshKey` field) on every connect, with the session from `BW_SESSION`, sshr never sees the master password

## Sync

- every device has its own keys from a 32-byte seed in the keychain: Ed25519 for signing and ML-KEM-768 + X25519 (X-Wing) for receiving the vault key, there is no master password to guess
- a random vault key encrypts each host (XChaCha20-Poly1305, account, host ID and key epoch as associated data, padded to 512 bytes), each device gets the vault key in its own HPKE envelope
- the manifest lists hosts, blob hashes and trusted devices, it is MAC'd with the vault key, signed by the pushing device and chained to the previous manifest, a device accepts only a chain that continues what it saw, signed by a device it trusts, every manifest of the chain is checked by signature, the MAC with the vault key on the manifest it applies, so a device that missed several key changes still catches up
- a new device is trusted only after comparing its fingerprint on both screens, the invite code carries the inviting device's fingerprint, so the server can neither add its own device nor impersonate the inviter
- saved passwords travel inside the encryption and are sealed again on the receiving machine, private keys kept in sshr never leave their device
- 1Password and Bitwarden references never sync, a host from another device keeps the reference set on this machine only while its address, user, port and jump stay the same, otherwise it falls back to asking, otherwise one stolen device could point every other device at a different 1Password item and collect it
- removing a device revokes its token first, then rotates the vault key and re-encrypts every host, the new key is delivered to the other devices only after the manifest without that device is written, a removal that loses the race to another push plans again from the newer state, a delivery cut short resumes on the next sync of that device and the others wait for it
- limits: a new device trusts whatever the server shows first, a server can show two devices different histories (compare the state fingerprint in `sshr sync status`), the server sees host count, push times, addresses and device names, and can hold back changes, a removed device keeps what it downloaded

## Sync server

- stores device public keys, encrypted blobs and signed manifests, it cannot read hosts, it can only lose data or refuse service
- each device has its own bearer token, the server keeps its SHA-256, new accounts and joins are limited to 10 an hour per address, a joined device does nothing until approved
- a manifest is replaced only with `If-Match` on the current counter and only when every blob it names is stored, two devices pushing at once cannot overwrite each other
- blobs are content addressed (SHA-256, 1 MiB at most), unused blobs go after a day, the last 1000 manifests are kept for the history check
- TLS 1.3 only, plain HTTP only on loopback, one server per data directory

## MCP and REST

- neither returns or accepts passwords, private keys or 1Password and Bitwarden references, a host linked to a password manager is added in the app or the CLI
- `sshr mcp` listens on nothing, the assistant runs it as a child process over stdin and stdout, every command is logged to stderr
- `sshr serve` listens on a 0600 unix socket by default, a TCP port only on loopback and only with the token from `~/.sshr/api-token`, requests with an `Origin` header (web pages) or a non-loopback `Host` (DNS rebinding) are refused
- running commands is off by default in both

## Export to ssh config

- passwords and keys kept in sshr or 1Password are not exported
- a value ssh could read as another option (a newline, a quote, a space in an address) skips the host, so a synced host cannot add `ProxyCommand` to your config
