// Package sshcmd builds and runs ssh, scp, mosh and the agent for a saved
// host: the arguments of a connection, jump hosts, reuse of a connection,
// copying files, commands on the host, keys out of the vault, 1Password or
// Bitwarden, and the ssh binary to use
//
// It reads the vault through internal/vault, the keychain behind it is set
// by the front end (internal/app sets the system one), a binary that uses
// sshcmd without app has no keychain
package sshcmd

import "sshr.dev/internal/hosts"

// Env is what the code that runs ssh needs: the host store with its hooks,
// the held one inside a lock, and the "reuse" override of this run, nil
// means the setting decides
type Env struct {
	Hosts *hosts.Store
	Reuse *bool
}
