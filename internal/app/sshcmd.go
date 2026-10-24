package app

import (
	"os/exec"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"sshr.dev/internal/sshcmd"
)

// The names below are the ssh runner of internal/sshcmd as the front ends
// know it from app, types and errors are aliases so errors.Is and type
// switches see the same values

type (
	LaunchOptions = sshcmd.LaunchOptions
	SessionPlan   = sshcmd.SessionPlan
	RemoteResult  = sshcmd.RemoteResult
)

const (
	ControlPersist   = sshcmd.ControlPersist
	DefaultKeyName   = sshcmd.DefaultKeyName
	DefaultSKKeyName = sshcmd.DefaultSKKeyName
	ProxyCommandName = sshcmd.ProxyCommandName
	UploadTTL        = sshcmd.UploadTTL
)

var ErrAsksPassword = sshcmd.ErrAsksPassword

func AgentKeys(name string) ([]*agent.Key, error)       { return sshcmd.AgentKeys(name) }
func AskTerminal(prompt string) (string, error)         { return sshcmd.AskTerminal(prompt) }
func AttachAuth(cmd *exec.Cmd, h *Host) (func(), error) { return sshcmd.AttachAuth(cmd, h) }
func ControlDir() (string, error)                       { return sshcmd.ControlDir() }
func IsAskpassCall(args []string) bool                  { return sshcmd.IsAskpassCall(args) }
func MoshStartFailed(code int, elapsed time.Duration) bool {
	return sshcmd.MoshStartFailed(code, elapsed)
}
func ReadPublicKey(path string) (string, error) { return sshcmd.ReadPublicKey(path) }
func RunAskpass(prompt string) int              { return sshcmd.RunAskpass(prompt) }
func SCPPath() (string, error)                  { return sshcmd.SCPPath() }
func SessionCommand(kind string) string         { return sshcmd.SessionCommand(kind) }
func SessionScript(kind string) string          { return sshcmd.SessionScript(kind) }
func SSHArgs(h *Host) []string                  { return sshcmd.SSHArgs(h) }
func SSHCommand(args ...string) *exec.Cmd       { return sshcmd.SSHCommand(args...) }
func SSHPath() (string, error)                  { return sshcmd.SSHPath() }
func StripAuthEnv(env []string) []string        { return sshcmd.StripAuthEnv(env) }

func KeygenArgs(path, comment string, noPassphrase bool) ([]string, error) {
	return sshcmd.KeygenArgs(path, comment, noPassphrase)
}

var SKKeyTypes = sshcmd.SKKeyTypes

func SKKeygenArgs(path, comment, typ string, resident, verify bool) ([]string, error) {
	return sshcmd.SKKeygenArgs(path, comment, typ, resident, verify)
}

func SKUnsupported(stderr string) bool { return sshcmd.SKUnsupported(stderr) }
