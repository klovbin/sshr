// Package app holds local vault storage and app settings (no UI).
package app

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	ErrHostEmpty    = errors.New("host_empty")
	ErrUserRequired = errors.New("user_required")
	ErrNotFound     = errors.New("not_found")
	ErrPortInvalid  = errors.New("port_invalid")
	// ErrPasswordRequired means PasswordSaved was chosen with no password
	ErrPasswordRequired = errors.New("password_required")
	// ErrKeyRequired means KeyVault was chosen with no key pasted
	ErrKeyRequired = errors.New("key_required")
	// ErrChanged means Update got a copy of the host older than the saved
	// one, a sync or another window saved it meanwhile
	ErrChanged = errors.New("host_changed")
)

// ParsePort reads a TCP port: digits only, 1–65535.
func ParsePort(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, ErrPortInvalid
	}
	return n, nil
}

// AmbiguousError means a query matched several hosts; Hosts lists them so the
// caller can ask for an exact ID instead of guessing.
type AmbiguousError struct {
	Query string
	Hosts []Host
}

func (e *AmbiguousError) Error() string {
	return fmt.Sprintf("%q matches %d hosts", e.Query, len(e.Hosts))
}

// Host is one SSH target
type Host struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
	User string `json:"user"`
	Key  string `json:"key,omitempty"`
	// KeyMode is KeyVault for a private key stored inside sshr, empty for
	// a key file in Key or no key
	KeyMode string `json:"key_mode,omitempty"`
	// KeyData is a pasted private key, in memory only, set it to save a
	// new one
	KeyData []byte `json:"-"`
	// KeyPassphrase opens a passphrase-protected KeyData, never stored
	KeyPassphrase string `json:"-"`
	// KeySealed is the private key encrypted with the vault key
	KeySealed string `json:"key_sealed,omitempty"`
	// KeyPub is the public half of the stored key, authorized_keys format
	KeyPub string `json:"key_pub,omitempty"`
	// KeyRef is the 1Password secret reference of the private key of an
	// SSH Key item, op://vault/item/private key, for KeyOnePassword
	KeyRef string `json:"key_ref,omitempty"`
	// Agent is the agent of a KeyAgent host, system (empty), 1password or
	// the path of an agent socket
	Agent string `json:"agent,omitempty"`
	// AgentKey picks one key of the agent by fingerprint or comment when
	// saving, it is turned into KeyPub and not stored
	AgentKey string `json:"-"`
	// PasswordMode is PasswordSaved, PasswordAsk, PasswordOnePassword or
	// empty
	PasswordMode string `json:"password_mode,omitempty"`
	// Password is the plain password, in memory only, set it to save a new
	// one, Unlock fills it from PasswordSealed before connecting
	Password string `json:"-"`
	// PasswordRef is the 1Password secret reference of the password, for
	// PasswordOnePassword
	PasswordRef string `json:"password_ref,omitempty"`
	// PasswordSealed is the password encrypted with the vault key
	PasswordSealed string `json:"password_sealed,omitempty"`
	// PlainPassword is the unencrypted "password" field older versions
	// wrote, it is sealed and dropped on the next save that can reach the
	// keychain
	PlainPassword string `json:"password,omitempty"`
	// Jump lists hosts to go through, "a,b": saved host names/IDs or
	// [user@]host[:port], empty means a direct connection
	Jump string `json:"jump,omitempty"`
	// Gateway is a jump spec tried only when the host does not answer
	// directly, for a server reachable at the office and through a bastion
	// from home, empty means no fallback, a host with Jump cannot have one
	Gateway string `json:"gateway,omitempty"`
	// Session is "tmux" or "zellij" to attach to a remote session named
	// SessionName on connect, empty means a plain shell
	Session string `json:"session,omitempty"`
	// Forwards are named port forwards, started with connect -F or as a
	// tunnel with sshr tunnel
	Forwards []Forward `json:"forwards,omitempty"`
	// Tags group hosts (prod, db, client-x), lower case, sorted
	Tags      []string  `json:"tags,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	// LastConnected is the end of the last session ssh opened, set by
	// MarkConnected, it stays on this machine and does not sync
	LastConnected *time.Time `json:"last_connected,omitempty"`
	// Rev counts the saves of the host on this machine, Add, Update and
	// Import raise it, Update refuses a copy with another Rev, 0 skips the
	// check, it stays on this machine and does not sync
	Rev int `json:"rev,omitempty"`

	// route is the Gateway when the last ConnectArgs found the host down
	// directly
	route string
	// extra are the keys of the host file this build does not know, a
	// field a newer sshr wrote, kept through every save (record.go)
	extra map[string]json.RawMessage
	// format is the "version" of the host file, 0 and 1 are today's, a
	// newer one is read and never written (record.go)
	format int
}

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

// hostStore reads and writes the host files, what a change needs from
// the parts that run programs comes through hooks, so it runs none itself
type hostStore struct {
	Dir   string
	hooks hostHooks
	// held is set on the copy that locked hands out, its methods do not
	// take the lock again
	held bool
}

// hostHooks are the steps of a change that run programs or touch other
// files, a nil hook is skipped
type hostHooks struct {
	// agentKey turns AgentKey into the public key, it asks the agent
	agentKey func(*Host) error
	// keyPub reads the public half of a key kept in a password manager
	keyPub func(*Host) error
	// storeSecret puts a password into 1Password before the host is saved
	storeSecret func(*Host) error
	// changed runs after a save or a removal, with the held store
	changed func(tx *hostStore)
}

// hostLockWait is how long a save waits for another sshr process, a save
// can wait on the keychain or 1Password, so it is longer than a write
const hostLockWait = 30 * time.Second

// locked runs fn under the lock of the host folder, a read, a change and
// a write of hosts by one process never interleave with another process,
// fn gets a Store whose methods do not lock again, the lock file sits in
// the host folder, List reads only .json files
func (s *hostStore) locked(fn func(tx *hostStore) error) error {
	if s.held {
		return fn(s)
	}
	unlock, err := waitLock(filepath.Join(s.Dir, ".lock"), "saving hosts", hostLockWait)
	if err != nil {
		return err
	}
	defer unlock()
	tx := *s
	tx.held = true
	return fn(&tx)
}

// Locked runs fn under the lock of the host folder, see locked, the sync
// reads a host, decides and writes it in one go with it
func (s *hostStore) Locked(fn func(tx *hostStore) error) error { return s.locked(fn) }

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

// upgradeSeals seals passwords saved by an older sshr again for their
// destination (v1 to v2), until then a host file whose address is changed
// outside sshr would still open its password, it touches the keychain only
// when such a host exists and leaves a host as it is when that fails
func (s *hostStore) upgradeSeals() {
	s.locked(func(tx *hostStore) error {
		tx.upgradeSealsLocked()
		return nil
	})
}

func (s *hostStore) upgradeSealsLocked() {
	hosts, err := s.List()
	if err != nil {
		return
	}
	// the vault key is asked for once, and only when a clear password is
	// there to seal, a keychain out of reach does not make every start
	// rewrite those hosts and wait for it
	asked, ready := false, false
	keyReady := func() bool {
		if !asked {
			_, err := VaultKey()
			asked, ready = true, err == nil
		}
		return ready
	}
	for i := range hosts {
		h := &hosts[i]
		// a host of a newer format is not written by this build, opening
		// its seal would only reach the keychain on every start
		if h.format > hostFormat {
			continue
		}
		changed := false
		if h.PasswordMode == PasswordSaved && strings.HasPrefix(h.PasswordSealed, sealPrefix) {
			if plain, err := unseal(h.PasswordSealed, h.ID, "password"); err == nil {
				h.Password, h.PasswordSealed = string(plain), ""
				changed = true
			}
		}
		// a password an old version wrote in clear, save seals it once the
		// keychain works and leaves it as it is while there is none
		if h.PasswordMode == PasswordSaved && h.PlainPassword != "" && h.PasswordSealed == "" && keyReady() {
			changed = true
		}
		// a stored key sealed before keys were bound to their destination
		if h.KeyMode == KeyVault && strings.HasPrefix(h.KeySealed, sealPrefix) {
			if plain, err := unseal(h.KeySealed, h.ID, "key"); err == nil {
				h.KeyData, h.KeySealed = plain, ""
				changed = true
			}
		}
		if changed {
			s.save(h)
		}
	}
}

// Add saves a new host, ID and CreatedAt are set here
func (s *hostStore) Add(in Host) (out *Host, err error) {
	err = s.locked(func(tx *hostStore) error {
		out, err = tx.add(in)
		return err
	})
	return out, err
}

func (s *hostStore) add(in Host) (*Host, error) {
	h, err := cleanHost(in, s.hooks.agentKey)
	if err != nil {
		return nil, err
	}
	if err := s.keyPub(&h); err != nil {
		return nil, err
	}
	if err := needSecret(&h); err != nil {
		return nil, err
	}
	if h.ID, err = newID(); err != nil {
		return nil, err
	}
	h.CreatedAt = time.Now().UTC()
	h.Rev = 1
	if err := s.save(&h); err != nil {
		return nil, err
	}
	return &h, nil
}

// userRe is what a login name may hold, letters, digits, . _ @ and - for
// user@domain and DOMAIN\user too, never a leading -, a space or a shell
// character, ssh and config lines take it as it is
var userRe = regexp.MustCompile(`^[A-Za-z0-9._@\\][A-Za-z0-9._@\\-]*$`)

// cleanHost trims and checks the fields of a host before it is saved
func cleanHost(h Host, agentKey func(*Host) error) (Host, error) {
	h.Name = strings.TrimSpace(h.Name)
	h.Host = strings.TrimSpace(h.Host)
	h.User = strings.TrimSpace(h.User)
	if h.Host == "" {
		return h, ErrHostEmpty
	}
	if err := checkAddress(h.Host); err != nil {
		return h, err
	}
	if h.User == "" {
		return h, ErrUserRequired
	}
	if !userRe.MatchString(h.User) {
		return h, fmt.Errorf("user %q has characters a login name cannot have", h.User)
	}
	if h.Name == "" {
		h.Name = h.Host
	}
	if h.Port == 0 {
		h.Port = 22
	}
	if h.Port < 1 || h.Port > 65535 {
		return h, ErrPortInvalid
	}
	h.Key = strings.TrimSpace(h.Key)
	// a password is kept as typed, spaces at the ends can be part of it
	if h.Password != "" && h.PasswordMode == "" {
		h.PasswordMode = PasswordSaved
	}
	switch h.PasswordMode {
	case "", PasswordAsk, PasswordSaved, PasswordOnePassword, PasswordBitwarden:
	default:
		return h, fmt.Errorf("unknown password mode %q", h.PasswordMode)
	}
	if len(h.KeyData) > 0 {
		h.KeyMode = KeyVault
	}
	if h.KeyMode != KeyOnePassword && h.KeyMode != KeyBitwarden {
		h.KeyRef = ""
	}
	if h.KeyMode != KeyAgent {
		h.Agent, h.AgentKey = "", ""
	}
	switch h.KeyMode {
	case "":
		h.KeyData, h.KeyPassphrase, h.KeySealed, h.KeyPub = nil, "", "", ""
	case KeyVault:
		h.Key = ""
		if len(h.KeyData) > 0 {
			if err := prepareVaultKey(&h); err != nil {
				return h, err
			}
		}
	case KeyAgent:
		h.Key, h.KeyData, h.KeyPassphrase, h.KeySealed = "", nil, "", ""
		if err := checkAgent(&h); err != nil {
			return h, err
		}
		if agentKey != nil {
			if err := agentKey(&h); err != nil {
				return h, err
			}
		}
	case KeyOnePassword:
		h.Key, h.KeyData, h.KeyPassphrase, h.KeySealed = "", nil, "", ""
		h.KeyRef = strings.TrimSpace(h.KeyRef)
		if err := checkOPRef(h.KeyRef); err != nil {
			return h, err
		}
	case KeyBitwarden:
		h.Key, h.KeyData, h.KeyPassphrase, h.KeySealed = "", nil, "", ""
		h.KeyRef = strings.TrimSpace(h.KeyRef)
		if err := checkBWRef(h.KeyRef); err != nil {
			return h, err
		}
	default:
		return h, fmt.Errorf("unknown key mode %q", h.KeyMode)
	}
	if h.Key != "" || h.KeyMode != "" {
		h.PasswordMode = ""
	}
	if h.PasswordMode != PasswordSaved {
		h.PasswordSealed, h.PlainPassword = "", ""
	}
	if h.PasswordMode != PasswordSaved && h.PasswordMode != PasswordOnePassword {
		h.Password = ""
	}
	switch h.PasswordMode {
	case PasswordOnePassword:
		h.PasswordRef = strings.TrimSpace(h.PasswordRef)
		if h.PasswordRef != "" {
			if err := checkOPRef(h.PasswordRef); err != nil {
				return h, err
			}
		}
	case PasswordBitwarden:
		// bw has no "create" here, the item is made in Bitwarden first
		h.Password = ""
		h.PasswordRef = strings.TrimSpace(h.PasswordRef)
		if err := checkBWRef(h.PasswordRef); err != nil {
			return h, err
		}
	default:
		h.PasswordRef = ""
	}
	var err error
	if h.Jump, err = checkJump(h.Jump, h.Name); err != nil {
		return h, err
	}
	if h.Gateway, err = checkJump(h.Gateway, h.Name); err != nil {
		return h, fmt.Errorf("gateway: %w", err)
	}
	if h.Gateway != "" && h.Jump != "" {
		return h, fmt.Errorf("host %q always goes through %s, a gateway is only for a host reached directly", h.Name, h.Jump)
	}
	h.Session = strings.TrimSpace(h.Session)
	if err := checkSession(h.Session); err != nil {
		return h, err
	}
	if err := checkForwards(h.Forwards); err != nil {
		return h, err
	}
	if h.Tags, err = CleanTags(h.Tags); err != nil {
		return h, err
	}
	return h, nil
}

func (s *hostStore) List() ([]Host, error) {
	hosts, _, err := s.ListAll()
	return hosts, err
}

// ListAll is List that also names the IDs of host files that exist but do
// not load, the sync must not take such a host for a deleted one
func (s *hostStore) ListAll() ([]Host, []string, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	out := make([]Host, 0, len(entries))
	var broken []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := ReadFileShared(filepath.Join(s.Dir, e.Name()))
		if err != nil {
			broken = append(broken, strings.TrimSuffix(e.Name(), ".json"))
			continue
		}
		h, err := decodeHost(b)
		if err != nil {
			broken = append(broken, strings.TrimSuffix(e.Name(), ".json"))
			continue
		}
		// The file name is the source of truth: Delete builds its path from ID.
		h.ID = strings.TrimSuffix(e.Name(), ".json")
		if h.PlainPassword != "" && h.PasswordMode == "" && h.Key == "" {
			h.PasswordMode = PasswordSaved
		}
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, broken, nil
}

// Find resolves a query by exact ID, then name, then host address, then ID
// prefix. A tier with several matches is an error: picking one would let rm or
// connect hit the wrong server.
func (s *hostStore) Find(query string) (*Host, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, ErrNotFound
	}
	hosts, err := s.List()
	if err != nil {
		return nil, err
	}
	tiers := []func(h Host) bool{
		func(h Host) bool { return h.ID == query },
		func(h Host) bool { return strings.EqualFold(h.Name, query) },
		func(h Host) bool { return strings.EqualFold(h.Host, query) },
		func(h Host) bool { return strings.HasPrefix(h.ID, query) },
	}
	for _, match := range tiers {
		var found []Host
		for _, h := range hosts {
			if match(h) {
				found = append(found, h)
			}
		}
		switch len(found) {
		case 0:
			continue
		case 1:
			return &found[0], nil
		default:
			return nil, &AmbiguousError{Query: query, Hosts: found}
		}
	}
	return nil, ErrNotFound
}

func (s *hostStore) Delete(id string) error {
	return s.locked(func(tx *hostStore) error { return tx.delete(id) })
}

func (s *hostStore) delete(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return ErrNotFound
	}
	path := filepath.Join(s.Dir, id+".json")
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	os.Remove(filepath.Join(s.Dir, id+".pub"))
	s.changed()
	return nil
}

// Update rewrites an existing host with the fields of in, ID, CreatedAt,
// LastConnected and Gateway are kept, jump hosts in in drop the gateway, a
// Rev in in that is not the saved one returns ErrChanged and saves nothing,
// a copy read before a sync or another save would undo it, in.Rev 0
// overwrites without the check
func (s *hostStore) Update(id string, in Host) (out *Host, err error) {
	err = s.locked(func(tx *hostStore) error {
		out, err = tx.update(id, in, false)
		return err
	})
	return out, err
}

// SetGateway sets the gateway of host id, empty removes it, Update keeps
// the gateway because a form without that field would erase it
func (s *hostStore) SetGateway(id, gateway string) (out *Host, err error) {
	err = s.locked(func(tx *hostStore) error {
		cur, err := tx.Find(id)
		if err != nil {
			return err
		}
		in := *cur
		in.Gateway, in.Rev = gateway, 0
		out, err = tx.update(id, in, true)
		return err
	})
	return out, err
}

func (s *hostStore) update(id string, in Host, setGateway bool) (*Host, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, ErrNotFound
	}
	cur, err := s.Find(id)
	if err != nil {
		return nil, err
	}
	if in.Rev != 0 && in.Rev != cur.Rev {
		return nil, ErrChanged
	}
	if !setGateway {
		in.Gateway = cur.Gateway
		if strings.TrimSpace(in.Jump) != "" {
			in.Gateway = ""
		}
	}
	h, err := cleanHost(in, s.hooks.agentKey)
	if err != nil {
		return nil, err
	}
	// no new password typed keeps the saved one, sealed again for the new
	// destination when the address, user, port or jump hosts changed
	if h.PasswordMode == PasswordSaved && h.Password == "" && h.PasswordSealed == "" && h.PlainPassword == "" {
		h.PasswordSealed, h.PlainPassword = cur.PasswordSealed, cur.PlainPassword
	}
	if h.PasswordMode == PasswordSaved && h.Password == "" && h.PasswordSealed != "" && h.PasswordSealed == cur.PasswordSealed && destination(h) != destination(*cur) {
		plain, err := unsealFor(cur.PasswordSealed, cur.ID, "password", destination(*cur))
		if errors.Is(err, ErrSealBroken) {
			// a field edited in the file by hand breaks the seal, an edit
			// that puts the host back where the password was sealed for
			// (sshr gateway --off after a gateway added by hand) opens it
			plain, err = unsealFor(cur.PasswordSealed, cur.ID, "password", destination(h))
		}
		if err != nil {
			return nil, fmt.Errorf("the saved password of %s does not open, type it again: %v", cur.Name, err)
		}
		h.Password, h.PasswordSealed = string(plain), ""
	}
	// no new key pasted keeps the stored one
	if h.KeyMode == KeyVault && len(h.KeyData) == 0 && h.KeySealed == "" {
		h.KeySealed, h.KeyPub = cur.KeySealed, cur.KeyPub
	}
	if h.KeyMode == KeyVault && len(h.KeyData) == 0 && h.KeySealed != "" && h.KeySealed == cur.KeySealed && destination(h) != destination(*cur) {
		plain, err := reopenKey(cur, h)
		if err != nil {
			return nil, err
		}
		h.KeyData, h.KeySealed = plain, ""
	}
	// the 1Password item of the password stays the same unless another one
	// is given
	if h.PasswordMode == PasswordOnePassword && h.PasswordRef == "" {
		h.PasswordRef = cur.PasswordRef
	}
	if err := s.keyPub(&h); err != nil {
		return nil, err
	}
	if err := needSecret(&h); err != nil {
		return nil, err
	}
	h.ID, h.CreatedAt, h.Rev = cur.ID, cur.CreatedAt, cur.Rev+1
	// only MarkConnected sets it, a host built from form fields has none
	h.LastConnected = cur.LastConnected
	// the fields of a newer sshr are not in a form this build drew, and a
	// file of a newer format stays unwritten
	h.extra, h.format = maps.Clone(cur.extra), cur.format
	if err := s.save(&h); err != nil {
		return nil, err
	}
	return &h, nil
}

// Import saves a host that came from another device under its own ID and
// creation time, a password in it is sealed with this machine's vault key,
// with no keychain the host is not written rather than written in the
// clear, a private key stored in sshr never travels, the local one is kept
func (s *hostStore) Import(in Host) (out *Host, err error) {
	err = s.locked(func(tx *hostStore) error {
		out, err = tx.importHost(in)
		return err
	})
	return out, err
}

func (s *hostStore) importHost(in Host) (*Host, error) {
	id := strings.TrimSpace(in.ID)
	if !validID(id) {
		return nil, fmt.Errorf("bad host id %q", id)
	}
	created := in.CreatedAt
	var cur *Host
	if h, err := s.Find(id); err == nil && h.ID == id {
		cur = h
	}
	in, _ = FromOtherDevice(in, cur)
	if in.KeyMode == KeyVault {
		in.KeyData = nil
		in.KeySealed = ""
		if cur != nil && cur.KeyMode == KeyVault && cur.KeyPub == in.KeyPub {
			in.KeySealed = cur.KeySealed
			if destination(in) != destination(*cur) {
				// another device moved the host, the key stored here does
				// not follow an address it chose, it is not used until the
				// user pastes it again here (FromOtherDevice says so)
				in.KeySealed = ""
			}
		}
	}
	in.PlainPassword, in.PasswordSealed = "", ""
	// the unknown keys the payload carried, and the local ones of the
	// host here
	if cur != nil {
		in.extra = mergeExtra(in.extra, cur.extra)
	}
	if cur != nil && in.format < cur.format {
		in.format = cur.format
	}
	// jump hosts win over a gateway, as in Update, refusing the host would
	// repeat the same sync error on every run
	if strings.TrimSpace(in.Jump) != "" {
		in.Gateway = ""
	}
	h, err := cleanHost(in, s.hooks.agentKey)
	if err != nil {
		return nil, err
	}
	if h.PasswordMode == PasswordSaved && h.Password == "" {
		return nil, fmt.Errorf("host %s came without its password", h.Name)
	}
	h.ID, h.CreatedAt, h.Rev = id, created, 1
	if cur != nil {
		h.Rev = cur.Rev + 1
	}
	if err := s.save(&h); err != nil {
		return nil, err
	}
	return &h, nil
}

// FromOtherDevice drops what a host from another device must not decide
// on this machine, references to secrets here (1Password items) would make
// this machine read them and hand them to the host's server, local is the
// same host as saved here or nil, its references are kept, without one
// the password is asked and the key falls back to the default ssh keys,
// notes say what the user has to set again here, hooks and importers add
// their fields to this list
func FromOtherDevice(in Host, local *Host) (Host, []string) {
	var notes []string
	// a reference set here is only for the place it was set for, a host
	// whose address, user, port or jump changed on the other device would
	// carry this machine's secret to a new server
	same := local != nil && sameDestination(in, *local)
	if local != nil && !same && (local.PasswordRef != "" || local.KeyRef != "") {
		notes = append(notes, "the host now points elsewhere ("+in.Dest()+"), the password manager reference set here is dropped, set it again if that is right")
	}
	if local != nil && !same && local.KeyMode == KeyVault && local.KeySealed != "" {
		notes = append(notes, "the host now points elsewhere ("+in.Dest()+"), the key stored here is not used for it, paste it again here if that is right")
	}
	// a key file and an agent name places on this machine, like a reference
	// they stay only for the destination they were set for, a host that
	// points elsewhere falls back to the default ssh keys
	if local != nil && !same && (in.Key != "" || in.Agent != "" || in.KeyMode == KeyAgent) {
		if in.KeyMode == KeyAgent {
			in.KeyMode, in.KeyPub = "", ""
		}
		in.Key, in.Agent = "", ""
		notes = append(notes, "the host now points elsewhere ("+in.Dest()+"), its key file and agent are not used for it, ssh uses its default keys, set them again here if that is right")
	}
	// for a host that keeps its destination they come from this machine,
	// empty ones too, another device does not pick which key ssh offers
	if same {
		if in.KeyMode == KeyAgent && local.KeyMode != KeyAgent {
			in.KeyMode, in.KeyPub = "", ""
			notes = append(notes, "the host uses an ssh agent on the other device, the agent is set on each machine, until then ssh uses its default keys")
		}
		if in.KeyMode == KeyAgent {
			in.KeyPub = local.KeyPub
		}
		in.Key, in.Agent = local.Key, local.Agent
	}
	if name := managerName(in.PasswordMode); name != "" {
		if same && local.PasswordMode == in.PasswordMode && local.PasswordRef != "" {
			in.PasswordRef = local.PasswordRef
		} else {
			in.PasswordMode, in.PasswordRef = PasswordAsk, ""
			notes = append(notes, "the password is in "+name+" on the other device, set its reference here, until then it is asked")
		}
	} else {
		in.PasswordRef = ""
	}
	if name := managerName(in.KeyMode); name != "" {
		if same && local.KeyMode == in.KeyMode && local.KeyRef != "" {
			in.KeyRef, in.KeyPub = local.KeyRef, local.KeyPub
		} else {
			in.KeyMode, in.KeyRef, in.KeyPub = "", "", ""
			notes = append(notes, "the key is in "+name+" on the other device, set its reference here, until then ssh uses its default keys")
		}
	} else {
		in.KeyRef = ""
	}
	// when this machine last connected is its own business
	in.LastConnected = nil
	if local != nil {
		in.LastConnected = local.LastConnected
	}
	return in, notes
}

// MarkConnected records that a session to host id ended after ssh had
// opened it, recent hosts are listed first with sshr list --recent
func (s *hostStore) MarkConnected(id string) error {
	return s.locked(func(tx *hostStore) error { return tx.markConnected(id) })
}

func (s *hostStore) markConnected(id string) error {
	h, err := s.Find(id)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	h.LastConnected = &now
	return s.save(h)
}

// SortRecent orders hosts by their last connection, newest first, hosts
// never connected keep their order at the end
func SortRecent(hosts []Host) {
	sort.SliceStable(hosts, func(i, j int) bool {
		a, b := hosts[i].LastConnected, hosts[j].LastConnected
		if a == nil || b == nil {
			return a != nil && b == nil
		}
		return a.After(*b)
	})
}

// Ago says how long ago t was in a few characters, "-" for never
func Ago(t *time.Time, now time.Time) string {
	if t == nil {
		return "-"
	}
	d := now.Sub(*t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + " min ago"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d/time.Hour)) + " h ago"
	default:
		return strconv.Itoa(int(d/(24*time.Hour))) + " d ago"
	}
}

// addressRe is a host name, an ssh config alias, an IPv4 or an IPv6
// address, the address reaches %h in ProxyCommand, which ssh runs with the
// shell and does not sanitize before OpenSSH 9.6
var addressRe = regexp.MustCompile(`^(?:[A-Za-z0-9_][A-Za-z0-9._-]*|\[?[0-9A-Fa-f:.]+\]?)$`)

// checkAddress refuses an address with characters a shell or ssh would
// read as more than a name
func checkAddress(addr string) error {
	if !addressRe.MatchString(addr) {
		return fmt.Errorf("address %q: use a host name or an IP address", addr)
	}
	return nil
}

// sameDestination tells whether two versions of a host go to the same
// server the same way
func sameDestination(a, b Host) bool {
	return strings.EqualFold(strings.TrimSpace(a.Host), strings.TrimSpace(b.Host)) &&
		strings.TrimSpace(a.User) == strings.TrimSpace(b.User) &&
		effectivePort(a.Port) == effectivePort(b.Port) &&
		strings.ReplaceAll(a.Jump, " ", "") == strings.ReplaceAll(b.Jump, " ", "") &&
		strings.ReplaceAll(a.Gateway, " ", "") == strings.ReplaceAll(b.Gateway, " ", "")
}

// destination is what a saved password is sealed for, the server it may
// be sent to, the gateway is added only when set, so passwords sealed
// before gateways existed still open
func destination(h Host) string {
	d := strings.ToLower(strings.TrimSpace(h.Host)) + "\x00" + strings.TrimSpace(h.User) + "\x00" +
		strconv.Itoa(effectivePort(h.Port)) + "\x00" + strings.ReplaceAll(h.Jump, " ", "")
	if gw := strings.ReplaceAll(h.Gateway, " ", ""); gw != "" {
		d += "\x00gateway\x00" + gw
	}
	return d
}

func effectivePort(p int) int {
	if p == 0 {
		return 22
	}
	return p
}

// managerName names the password manager a mode reads from, empty for
// modes that keep the secret in sshr or nowhere
func managerName(mode string) string {
	switch mode {
	case PasswordOnePassword:
		return "1Password"
	case PasswordBitwarden:
		return "Bitwarden"
	}
	return ""
}

// Duplicate saves a copy of host id under a new ID and name, its saved
// password and stored key are sealed again for the new ID, the sync keeps
// the losing side of a conflict this way
func (s *hostStore) Duplicate(id, name string) (out *Host, err error) {
	err = s.locked(func(tx *hostStore) error {
		out, err = tx.duplicate(id, name)
		return err
	})
	return out, err
}

func (s *hostStore) duplicate(id, name string) (*Host, error) {
	cur, err := s.Find(id)
	if err != nil {
		return nil, err
	}
	h := *cur
	// a copy carries the unknown keys but not the local ones, a newer sshr
	// may bind those to this host's ID
	h.extra = nil
	for k, v := range cur.extra {
		if !strings.HasPrefix(k, localPrefix) {
			if h.extra == nil {
				h.extra = map[string]json.RawMessage{}
			}
			h.extra[k] = v
		}
	}
	// only a password sealed by sshr has to be opened and sealed again, a
	// password manager entry keeps its reference and is not read at all
	if h.PasswordMode == PasswordSaved {
		if err := Unlock(&h); err != nil {
			return nil, err
		}
	}
	if h.KeyMode == KeyVault && h.KeySealed != "" {
		plain, err := unsealFor(h.KeySealed, h.ID, "key", destination(h))
		if err != nil {
			return nil, err
		}
		h.KeyData, h.KeySealed = plain, ""
	}
	h.ID, h.Name, h.PasswordSealed, h.PlainPassword = "", name, "", ""
	return s.Add(h)
}

// validID accepts the IDs newID makes, the ID becomes a file name
func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// checkJump normalizes a jump spec and refuses one that names the host
// itself, which would loop
func checkJump(jump, name string) (string, error) {
	jump, err := normalizeJump(jump)
	if err != nil {
		return "", err
	}
	for _, p := range SplitJump(jump) {
		if strings.EqualFold(p, name) {
			return "", fmt.Errorf("host %q cannot jump through itself", name)
		}
		// A saved host name parses as a plain host too, so this only rejects
		// specs that can never work, like a bad port
		if _, err := ParseHop(p); err != nil {
			return "", err
		}
	}
	return jump, nil
}

// keyPub runs the keyPub hook
func (s *hostStore) keyPub(h *Host) error {
	if s.hooks.keyPub == nil {
		return nil
	}
	return s.hooks.keyPub(h)
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

// needSecret refuses PasswordSaved with no password and KeyVault with no
// key to save
func needSecret(h *Host) error {
	if h.PasswordMode == PasswordSaved && h.Password == "" && h.PasswordSealed == "" && h.PlainPassword == "" {
		return ErrPasswordRequired
	}
	// a host synced from a device that keeps its key has KeyPub and no
	// sealed key here, it can still be edited
	if h.KeyMode == KeyVault && len(h.KeyData) == 0 && h.KeySealed == "" && h.KeyPub == "" {
		return ErrKeyRequired
	}
	if h.PasswordMode == PasswordOnePassword && h.Password == "" && h.PasswordRef == "" {
		return ErrPasswordRequired
	}
	return nil
}

// sealKey encrypts a newly pasted private key before the host is written,
// with no keychain the host is not saved, the key is never written
// unencrypted
func sealKey(h *Host) error {
	if h.KeyMode != KeyVault || len(h.KeyData) == 0 {
		return nil
	}
	// sealed for the server it may be offered to, like a saved password, a
	// host file edited to point elsewhere does not get the key
	sealed, err := sealFor(h.KeyData, h.ID, "key", destination(*h))
	if err != nil {
		return err
	}
	h.KeySealed = sealed
	return nil
}

// reopenKey opens the stored key of cur for a host h that keeps it while
// its destination changed through sshr, so it is sealed again for h, a
// seal that does not open for the file opens for h when h is the place it
// was sealed for (a field edited by hand and put back)
func reopenKey(cur *Host, h Host) ([]byte, error) {
	plain, err := unsealFor(cur.KeySealed, cur.ID, "key", destination(*cur))
	if errors.Is(err, ErrSealBroken) {
		plain, err = unsealFor(cur.KeySealed, cur.ID, "key", destination(h))
	}
	if err != nil {
		return nil, fmt.Errorf("the stored key of %s does not open, paste it again: %v", cur.Name, err)
	}
	return plain, nil
}

// sealPassword encrypts a new password, or an old unencrypted one, before
// the host is written, an old one stays as it was when the keychain is out
// of reach, a new one is refused then, it is never written unencrypted
func sealPassword(h *Host) error {
	if h.PasswordMode != PasswordSaved {
		return nil
	}
	plain := h.Password
	if plain == "" {
		plain = h.PlainPassword
	}
	if plain == "" {
		return nil
	}
	sealed, err := sealFor([]byte(plain), h.ID, "password", destination(*h))
	if err != nil {
		if h.Password == "" || h.Password == h.PlainPassword {
			return nil
		}
		return err
	}
	h.PasswordSealed, h.PlainPassword = sealed, ""
	return nil
}

// Unlock fills h.Password from the vault or 1Password before connecting, a
// host without a saved password is left as it is
func Unlock(h *Host) error {
	if h.Password != "" {
		return nil
	}
	if h.PasswordMode == PasswordOnePassword {
		pw, err := opRead(h.PasswordRef)
		if err != nil {
			return err
		}
		h.Password = string(pw)
		return nil
	}
	if h.PasswordMode == PasswordBitwarden {
		pw, err := bwPassword(h.PasswordRef)
		if err != nil {
			return err
		}
		h.Password = string(pw)
		return nil
	}
	if h.PasswordMode != PasswordSaved {
		return nil
	}
	switch {
	case h.PasswordSealed != "":
		plain, err := unsealFor(h.PasswordSealed, h.ID, "password", destination(*h))
		if errors.Is(err, ErrSealBroken) {
			return fmt.Errorf("the saved password of %s does not open here (keychain reset, the host copied from another machine, or its address changed outside sshr), save the password again", h.Name)
		}
		if err != nil {
			return err
		}
		h.Password = string(plain)
	case h.PlainPassword != "":
		h.Password = h.PlainPassword
	default:
		return fmt.Errorf("%s has no saved password, save it again", h.Name)
	}
	return nil
}

func (s *hostStore) save(h *Host) error {
	// a host of a newer format is refused before anything leaves the
	// process, a 1Password item made for a file that is then not written
	// would be left behind
	if h.format > hostFormat {
		return newerHostError(h)
	}
	if err := sealPassword(h); err != nil {
		return err
	}
	if err := sealKey(h); err != nil {
		return err
	}
	if s.hooks.storeSecret != nil {
		if err := s.hooks.storeSecret(h); err != nil {
			return err
		}
	}
	b, err := encodeHost(h)
	if err != nil {
		return err
	}
	path := filepath.Join(s.Dir, h.ID+".json")
	if err := WriteFileAtomic(path, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if err := s.writePub(h); err != nil {
		return err
	}
	s.changed()
	return nil
}

// changed runs the changed hook with this held store
func (s *hostStore) changed() {
	if s.hooks.changed != nil {
		s.hooks.changed(s)
	}
}

// hostsChanged rewrites the ssh config export when it is installed, the
// host is saved already, a failed export is reported and does not undo it
func (s *Store) hostsChanged() {
	if _, err := s.refreshSSHConfig(false); err != nil {
		fmt.Fprintf(os.Stderr, "sshr: ssh config export: %v\n", err)
	}
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// ParseDestination reads user@host[:port] or ssh://user@host[:port] into a
// host that is not saved, for connecting once, an IPv6 address goes in
// brackets when a port follows, a password in the string is refused so it
// cannot end up in the shell history
func ParseDestination(s string) (Host, error) {
	rest, isURL := strings.CutPrefix(s, "ssh://")
	rest = strings.TrimSuffix(rest, "/")
	user, addr, ok := strings.Cut(rest, "@")
	if !ok || user == "" {
		return Host{}, fmt.Errorf("%q is not user@host[:port]", s)
	}
	if strings.Contains(user, ":") {
		return Host{}, errors.New("a password in the address is refused, it would stay in the shell history, sshr asks for it or saves it")
	}
	if isURL && strings.ContainsAny(addr, "/?#") {
		return Host{}, fmt.Errorf("%q has a path, only ssh://user@host[:port] is taken", s)
	}
	host, port := addr, 22
	switch {
	case strings.HasPrefix(addr, "["):
		end := strings.Index(addr, "]")
		if end < 0 {
			return Host{}, fmt.Errorf("%q has an unclosed [", s)
		}
		host = addr[1:end]
		if tail := addr[end+1:]; tail != "" {
			p, err := parsePort(strings.TrimPrefix(tail, ":"))
			if err != nil || !strings.HasPrefix(tail, ":") {
				return Host{}, fmt.Errorf("%q has a bad port", s)
			}
			port = p
		}
	case strings.Count(addr, ":") == 1:
		h, p, _ := strings.Cut(addr, ":")
		n, err := parsePort(p)
		if err != nil {
			return Host{}, fmt.Errorf("%q has a bad port", s)
		}
		host, port = h, n
	}
	h, err := cleanHost(Host{Host: host, User: user, Port: port}, nil)
	if err != nil {
		return Host{}, err
	}
	return h, nil
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, errors.New("bad port")
	}
	return n, nil
}
