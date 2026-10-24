// Package sshconf reads the hosts of the user's ssh config into sshr
// (through ssh -G) and writes the saved hosts out as an ssh config file
// that ~/.ssh/config includes, so plain ssh, scp and editors reach them
package sshconf

import (
	"os"

	"sshr.dev/internal/fileio"
	"sshr.dev/internal/hosts"
	"sshr.dev/internal/sshcmd"
)

// Env is what the import and the export need: the ssh environment and the
// path of the export file, empty turns the export off
type Env struct {
	sshcmd.Env
	Out string
}

// locked runs fn under the lock of the host folder with the held store
func (e Env) locked(fn func(tx Env) error) error {
	return e.Hosts.Locked(func(held *hosts.Store) error {
		c := e
		c.Hosts = held
		return fn(c)
	})
}

// The short names below are the ones the code was written with in app

type (
	Host    = hosts.Host
	Forward = hosts.Forward
)

const (
	KeyAgent            = hosts.KeyAgent
	AgentOnePassword    = hosts.AgentOnePassword
	PasswordSaved       = hosts.PasswordSaved
	PasswordOnePassword = hosts.PasswordOnePassword
	PasswordBitwarden   = hosts.PasswordBitwarden
)

func SplitJump(spec string) []string    { return hosts.SplitJump(spec) }
func ExpandHome(path string) string     { return hosts.ExpandHome(path) }
func CheckPrivateKey(path string) error { return hosts.CheckPrivateKey(path) }

func ReadFileShared(path string) ([]byte, error) { return fileio.ReadFileShared(path) }

func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	return fileio.WriteFile(path, data, mode)
}
