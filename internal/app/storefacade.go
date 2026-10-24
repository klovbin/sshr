// Package app is the core the front ends use: the Store over package
// hosts, the ssh command lines, the password managers, the ssh config
// import and export, it sets the system keychain and the passphrase
// prompt of package vault
package app

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"sshr.dev/internal/hosts"

	"sshr.dev/internal/sshcmd"
)

// Store persists hosts as ~/.sshr/vault/hosts/<id>.json (0600).
type Store struct {
	Dir string
	// Reuse overrides the "reuse" setting for this run, nil means the
	// setting decides
	Reuse *bool
	// OPVault overrides the "op_vault" setting for this run
	OPVault *string
	// SSHConfigOut is where the hosts are exported for plain ssh, empty
	// turns the export off, it is rewritten on every change once installed
	SSHConfigOut string

	// tx is the held host store of a Store that Locked hands out, its
	// methods do not take the lock again
	tx *hostStore
}

// DefaultStore creates ~/.sshr/vault/hosts if needed.
func DefaultStore() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, ".sshr", "vault", "hosts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{Dir: dir, SSHConfigOut: filepath.Join(home, ".sshr", "ssh_config")}
	s.upgradeSeals()
	return s, nil
}

// fillKeyPub reads the public half of a key kept in 1Password or Bitwarden
// once, when the host does not have it yet, cleanHost only checks fields
// and runs no program, so a host is validated without op or bw
func fillKeyPub(h *Host) error {
	if h.KeyPub != "" {
		return nil
	}
	var pub string
	var err error
	switch h.KeyMode {
	case KeyOnePassword:
		pub, err = opKeyPub(h.KeyRef)
	case KeyBitwarden:
		pub, err = bwKeyPub(h.KeyRef)
	default:
		return nil
	}
	if err != nil {
		return err
	}
	h.KeyPub = pub
	return nil
}

// hostsChanged rewrites the ssh config export when it is installed, the
// host is saved already, a failed export is reported and does not undo it
func (s *Store) hostsChanged() {
	if _, err := s.confEnv().RefreshSSHConfig(false); err != nil {
		fmt.Fprintf(os.Stderr, "sshr: ssh config export: %v\n", err)
	}
}

// Unlock fills h.Password from the vault, 1Password or Bitwarden before
// connecting, see sshcmd.Unlock
func Unlock(h *Host) error { return sshcmd.Unlock(h) }

// The methods below are the host store as the front ends and the code
// that runs ssh know it, they hand the work to hostStore with the hooks
// that need this Store: the agent, the password managers and the ssh
// config export

// db is the host store of s, the held one inside Locked
func (s *Store) db() *hostStore {
	if s.tx != nil {
		return s.tx
	}
	return &hostStore{Dir: s.Dir, Hooks: s.hooks()}
}

// hooks connect a change of hosts to the agent, the password managers and
// the ssh config export of this Store
func (s *Store) hooks() hostHooks {
	return hostHooks{
		AgentKey:    sshcmd.PrepareAgentKey,
		KeyPub:      fillKeyPub,
		StoreSecret: s.opStorePassword,
		Changed: func(tx *hostStore) {
			c := *s
			c.tx = tx
			c.hostsChanged()
		},
	}
}

// Hosts is the host store of s with the hooks of s, for the sync client,
// a host it imports refreshes the ssh config export as any other change
func (s *Store) Hosts() *hosts.Store { return s.db() }

// locked runs fn under the lock of the host folder, fn gets a Store whose
// methods do not lock again
func (s *Store) locked(fn func(tx *Store) error) error {
	return s.db().Locked(func(tx *hostStore) error {
		c := *s
		c.tx = tx
		return fn(&c)
	})
}

// Locked runs fn under the lock of the host folder, see locked, the sync
// reads a host, decides and writes it in one go with it
func (s *Store) Locked(fn func(tx *Store) error) error { return s.locked(fn) }

// List returns the hosts this build can read, see hostStore.List
func (s *Store) List() ([]Host, error) { return s.db().List() }

// ListAll returns the hosts and the files that did not read
func (s *Store) ListAll() ([]Host, []string, error) { return s.db().ListAll() }

// Find resolves a host by ID, short ID, name or address
func (s *Store) Find(query string) (*Host, error) { return s.db().Find(query) }

// Add saves a new host
func (s *Store) Add(in Host) (*Host, error) { return s.db().Add(in) }

// Update changes a saved host
func (s *Store) Update(id string, in Host) (*Host, error) { return s.db().Update(id, in) }

// Import saves a host from another device or an importer
func (s *Store) Import(in Host) (*Host, error) { return s.db().Import(in) }

// Delete removes a host
func (s *Store) Delete(id string) error {
	if err := s.db().Delete(id); err != nil {
		return err
	}
	// a removed host leaves the hardware key list, the ID is never used
	// again, a list with dead IDs hides which hosts it still holds
	if st, err := LoadSettings(); err == nil && slices.Contains(st.HardwareKeyHosts, id) {
		st.ReleaseHardwareKey(id)
		return SaveSettings(st)
	}
	return nil
}

// Duplicate saves a copy of a host under another name
func (s *Store) Duplicate(id, name string) (*Host, error) { return s.db().Duplicate(id, name) }

// MarkConnected records that a session to the host ended
func (s *Store) MarkConnected(id string) error { return s.db().MarkConnected(id) }

// SetGateway sets or removes the gateway of a host
func (s *Store) SetGateway(id, gateway string) (*Host, error) { return s.db().SetGateway(id, gateway) }

// upgradeSeals seals passwords of an older sshr again, see hostStore
func (s *Store) upgradeSeals() { s.db().UpgradeSeals() }

// pubPath is where the public half of a key kept in sshr is written
func (s *Store) pubPath(h *Host) string { return s.db().PubPath(h) }

// writePub writes or removes the public half of the key of h
func (s *Store) writePub(h *Host) error { return s.db().WritePub(h) }
