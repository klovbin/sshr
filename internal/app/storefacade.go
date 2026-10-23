package app

// The methods below are the host store as the front ends and the code
// that runs ssh know it, they hand the work to hostStore with the hooks
// that need this Store: the agent, the password managers and the ssh
// config export

// db is the host store of s, the held one inside Locked
func (s *Store) db() *hostStore {
	if s.tx != nil {
		return s.tx
	}
	return &hostStore{Dir: s.Dir, hooks: s.hooks()}
}

// hooks connect a change of hosts to the agent, the password managers and
// the ssh config export of this Store
func (s *Store) hooks() hostHooks {
	return hostHooks{
		agentKey:    prepareAgentKey,
		keyPub:      fillKeyPub,
		storeSecret: s.opStorePassword,
		changed: func(tx *hostStore) {
			c := *s
			c.tx = tx
			c.hostsChanged()
		},
	}
}

// locked runs fn under the lock of the host folder, fn gets a Store whose
// methods do not lock again
func (s *Store) locked(fn func(tx *Store) error) error {
	return s.db().locked(func(tx *hostStore) error {
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
func (s *Store) Delete(id string) error { return s.db().Delete(id) }

// Duplicate saves a copy of a host under another name
func (s *Store) Duplicate(id, name string) (*Host, error) { return s.db().Duplicate(id, name) }

// MarkConnected records that a session to the host ended
func (s *Store) MarkConnected(id string) error { return s.db().MarkConnected(id) }

// SetGateway sets or removes the gateway of a host
func (s *Store) SetGateway(id, gateway string) (*Host, error) { return s.db().SetGateway(id, gateway) }

// upgradeSeals seals passwords of an older sshr again, see hostStore
func (s *Store) upgradeSeals() { s.db().upgradeSeals() }

// pubPath is where the public half of a key kept in sshr is written
func (s *Store) pubPath(h *Host) string { return s.db().pubPath(h) }

// writePub writes or removes the public half of the key of h
func (s *Store) writePub(h *Host) error { return s.db().writePub(h) }
