package app

import (
	"io"
	"time"

	"sshr.dev/internal/sshcmd"
)

// env is the ssh environment of s, built on every call so a Store inside
// Locked hands out the held host store and the hooks stay attached
func (s *Store) env() sshcmd.Env { return sshcmd.Env{Hosts: s.db(), Reuse: s.Reuse} }

// The methods below are the ssh runner as the front ends know it, see the
// methods of sshcmd.Env of the same name

func (s *Store) UploadImage(h *Host, data []byte, ext string, batch bool) (string, error) {
	return s.env().UploadImage(h, data, ext, batch)
}

func (s *Store) JumpArgs(h *Host) ([]string, error) { return s.env().JumpArgs(h) }

func (s *Store) ConnectArgs(h *Host) ([]string, error) { return s.env().ConnectArgs(h) }

func (s *Store) DirectArgs(h *Host) ([]string, error) { return s.env().DirectArgs(h) }

func (s *Store) ProxyHop(chain, targetHost, targetPort string) (*Host, []string, error) {
	return s.env().ProxyHop(chain, targetHost, targetPort)
}

func (s *Store) CloseMaster(h *Host) error { return s.env().CloseMaster(h) }

func (s *Store) CopyArgs(h *Host, send, legacy bool, sources []string, dest string) ([]string, error) {
	return s.env().CopyArgs(h, send, legacy, sources, dest)
}

func (s *Store) RunRemote(h *Host, command string, stdin io.Reader, timeout time.Duration) (*RemoteResult, error) {
	return s.env().RunRemote(h, command, stdin, timeout)
}

func (s *Store) PlanSession(h *Host, o LaunchOptions) (*SessionPlan, error) {
	return s.env().PlanSession(h, o)
}

func (s *Store) InstallKeyArgs(h *Host) ([]string, error) { return s.env().InstallKeyArgs(h) }
