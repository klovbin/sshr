package sshconf

import (
	"io"

	"sshr.dev/internal/hosts"
	"sshr.dev/internal/sshcmd"
)

// The tests were written against the Store of app, Store below gives them
// the same calls over an Env, a change of hosts rewrites an installed
// export as the hook of app does

const PasswordAsk = hosts.PasswordAsk

func FormatForwards(fs []Forward) string { return hosts.FormatForwards(fs) }

type Store struct {
	Dir          string
	SSHConfigOut string
}

func (s *Store) db() *hosts.Store {
	return &hosts.Store{Dir: s.Dir, Hooks: hosts.Hooks{
		AgentKey: sshcmd.PrepareAgentKey,
		Changed: func(tx *hosts.Store) {
			Env{Env: sshcmd.Env{Hosts: tx}, Out: s.SSHConfigOut}.RefreshSSHConfig(false)
		},
	}}
}

func (s *Store) conf() Env { return Env{Env: sshcmd.Env{Hosts: s.db()}, Out: s.SSHConfigOut} }

func (s *Store) Add(in Host) (*Host, error)               { return s.db().Add(in) }
func (s *Store) Update(id string, in Host) (*Host, error) { return s.db().Update(id, in) }
func (s *Store) Delete(id string) error                   { return s.db().Delete(id) }
func (s *Store) Find(query string) (*Host, error)         { return s.db().Find(query) }

func (s *Store) ImportSSHConfig(dryRun bool) ([]ImportItem, error) {
	return s.conf().ImportSSHConfig(dryRun)
}
func (s *Store) WriteSSHConfig(w io.Writer) ([]ExportItem, error) { return s.conf().WriteSSHConfig(w) }
func (s *Store) SSHConfigExported() bool                          { return s.conf().SSHConfigExported() }
func (s *Store) InstallSSHConfig() ([]ExportItem, error)          { return s.conf().InstallSSHConfig() }
func (s *Store) UninstallSSHConfig() error                        { return s.conf().UninstallSSHConfig() }
