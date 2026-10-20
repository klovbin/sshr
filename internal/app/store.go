// Package app holds local vault storage and app settings (no UI).
package app

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
)

// Password modes of a host, an empty mode means no password at all, the
// key file, ssh-agent or ssh config decide
const (
	// PasswordSaved keeps the password sealed with the vault key in the
	// host file, sshr hands it to ssh
	PasswordSaved = "saved"
	// PasswordAsk stores nothing, ssh asks on the terminal every time
	PasswordAsk = "ask"
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
	// Session is "tmux" or "zellij" to attach to a remote session named
	// SessionName on connect, empty means a plain shell
	Session string `json:"session,omitempty"`
	// Forwards are named port forwards, started with connect -F or as a
	// tunnel with sshr tunnel
	Forwards []Forward `json:"forwards,omitempty"`
	// Tags group hosts (prod, db, client-x), lower case, sorted
	Tags      []string  `json:"tags,omitempty"`
	CreatedAt time.Time `json:"created_at"`
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
	return &Store{Dir: dir, SSHConfigOut: filepath.Join(home, ".sshr", "ssh_config")}, nil
}

// Add saves a new host, ID and CreatedAt are set here
func (s *Store) Add(in Host) (*Host, error) {
	h, err := cleanHost(in)
	if err != nil {
		return nil, err
	}
	if err := needSecret(&h); err != nil {
		return nil, err
	}
	if h.ID, err = newID(); err != nil {
		return nil, err
	}
	h.CreatedAt = time.Now().UTC()
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
func cleanHost(h Host) (Host, error) {
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
		if err := prepareAgentKey(&h); err != nil {
			return h, err
		}
	case KeyOnePassword:
		h.Key, h.KeyData, h.KeyPassphrase, h.KeySealed = "", nil, "", ""
		h.KeyRef = strings.TrimSpace(h.KeyRef)
		if err := checkOPRef(h.KeyRef); err != nil {
			return h, err
		}
		if h.KeyPub == "" {
			pub, err := opKeyPub(h.KeyRef)
			if err != nil {
				return h, err
			}
			h.KeyPub = pub
		}
	case KeyBitwarden:
		h.Key, h.KeyData, h.KeyPassphrase, h.KeySealed = "", nil, "", ""
		h.KeyRef = strings.TrimSpace(h.KeyRef)
		if err := checkBWRef(h.KeyRef); err != nil {
			return h, err
		}
		if h.KeyPub == "" {
			pub, err := bwKeyPub(h.KeyRef)
			if err != nil {
				return h, err
			}
			h.KeyPub = pub
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

func (s *Store) List() ([]Host, error) {
	hosts, _, err := s.ListAll()
	return hosts, err
}

// ListAll is List that also names the IDs of host files that exist but do
// not load, the sync must not take such a host for a deleted one
func (s *Store) ListAll() ([]Host, []string, error) {
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
		b, err := os.ReadFile(filepath.Join(s.Dir, e.Name()))
		if err != nil {
			broken = append(broken, strings.TrimSuffix(e.Name(), ".json"))
			continue
		}
		var h Host
		if err := json.Unmarshal(b, &h); err != nil {
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
func (s *Store) Find(query string) (*Host, error) {
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

func (s *Store) Delete(id string) error {
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
	s.hostsChanged()
	return nil
}

// Update rewrites an existing host with the fields of in, ID and
// CreatedAt are kept
func (s *Store) Update(id string, in Host) (*Host, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, ErrNotFound
	}
	cur, err := s.Find(id)
	if err != nil {
		return nil, err
	}
	h, err := cleanHost(in)
	if err != nil {
		return nil, err
	}
	// no new password typed keeps the saved one
	if h.PasswordMode == PasswordSaved && h.Password == "" && h.PasswordSealed == "" && h.PlainPassword == "" {
		h.PasswordSealed, h.PlainPassword = cur.PasswordSealed, cur.PlainPassword
	}
	// no new key pasted keeps the stored one
	if h.KeyMode == KeyVault && len(h.KeyData) == 0 && h.KeySealed == "" {
		h.KeySealed, h.KeyPub = cur.KeySealed, cur.KeyPub
	}
	// the 1Password item of the password stays the same unless another one
	// is given
	if h.PasswordMode == PasswordOnePassword && h.PasswordRef == "" {
		h.PasswordRef = cur.PasswordRef
	}
	if err := needSecret(&h); err != nil {
		return nil, err
	}
	h.ID, h.CreatedAt = cur.ID, cur.CreatedAt
	if err := s.save(&h); err != nil {
		return nil, err
	}
	return &h, nil
}

// Import saves a host that came from another device under its own ID and
// creation time, a password in it is sealed with this machine's vault key,
// with no keychain the host is not written rather than written in the
// clear, a private key stored in sshr never travels, the local one is kept
func (s *Store) Import(in Host) (*Host, error) {
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
		}
	}
	in.PlainPassword, in.PasswordSealed = "", ""
	h, err := cleanHost(in)
	if err != nil {
		return nil, err
	}
	if h.PasswordMode == PasswordSaved && h.Password == "" {
		return nil, fmt.Errorf("host %s came without its password", h.Name)
	}
	h.ID, h.CreatedAt = id, created
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
	return in, notes
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
		strings.ReplaceAll(a.Jump, " ", "") == strings.ReplaceAll(b.Jump, " ", "")
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
func (s *Store) Duplicate(id, name string) (*Host, error) {
	cur, err := s.Find(id)
	if err != nil {
		return nil, err
	}
	h := *cur
	// only a password sealed by sshr has to be opened and sealed again, a
	// password manager entry keeps its reference and is not read at all
	if h.PasswordMode == PasswordSaved {
		if err := Unlock(&h); err != nil {
			return nil, err
		}
	}
	if h.KeyMode == KeyVault && h.KeySealed != "" {
		plain, err := unseal(h.KeySealed, h.ID, "key")
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
	sealed, err := seal(h.KeyData, h.ID, "key")
	if err != nil {
		return err
	}
	h.KeySealed = sealed
	return nil
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
	sealed, err := seal([]byte(plain), h.ID, "password")
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
		plain, err := unseal(h.PasswordSealed, h.ID, "password")
		if errors.Is(err, ErrSealBroken) {
			return fmt.Errorf("the saved password of %s does not open with the vault key of this machine (keychain reset or the host copied from another machine), save the password again", h.Name)
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

func (s *Store) save(h *Host) error {
	if err := sealPassword(h); err != nil {
		return err
	}
	if err := sealKey(h); err != nil {
		return err
	}
	if err := s.opStorePassword(h); err != nil {
		return err
	}
	b, err := json.MarshalIndent(h, "", "  ")
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
	s.hostsChanged()
	return nil
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

// PasswordFromSshr tells whether sshr hands the password to ssh, from the
// vault or from 1Password
func (h *Host) PasswordFromSshr() bool {
	return h.Key == "" && (h.PasswordMode == PasswordSaved || h.PasswordMode == PasswordOnePassword || h.PasswordMode == PasswordBitwarden)
}
