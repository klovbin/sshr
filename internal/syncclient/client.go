package syncclient

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"sshr.dev/internal/fileio"
	"sshr.dev/internal/hosts"
	"sshr.dev/internal/record"
	"sshr.dev/internal/syncproto"
	"sshr.dev/internal/vault"
)

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// entryState is what this device knows about one host since the last sync
type entryState struct {
	Lamport uint64 `json:"lamport"`
	Device  string `json:"device"`
	Blob    string `json:"blob,omitempty"`
	Deleted bool   `json:"deleted,omitempty"`
	// Local is a keyed hash of the host as it was written here at the last
	// sync, a different one means the host was changed here since
	Local string `json:"local,omitempty"`
}

type state struct {
	Server   string `json:"server"`
	Account  string `json:"account"`
	DeviceID string `json:"device_id"`
	Name     string `json:"name"`
	Token    string `json:"token"`
	Epoch    int    `json:"epoch"`
	Counter  uint64 `json:"counter"`
	Head     string `json:"head,omitempty"`
	// Trusted are the devices of the last verified manifest
	Trusted []syncproto.Device `json:"trusted,omitempty"`
	// Approver is the fingerprint of the inviting device, a joined device
	// trusts only it until it has verified its first manifest
	Approver string                `json:"approver,omitempty"`
	Entries  map[string]entryState `json:"entries"`
	// Skipped are remote entries this device could not import (a mode of a
	// newer sshr, a host that fails validation), a push carries them on
	// unchanged and every pull tries them again
	Skipped map[string]syncproto.Entry `json:"skipped,omitempty"`
	// Rotation is a key change that is in the manifest but whose key has
	// not reached every kept device yet, the next sync delivers it
	Rotation *rotation `json:"rotation,omitempty"`
	LastSync time.Time `json:"last_sync"`
	// Backend is the store of an account that is not sshr-sync
	Backend *BackendRef `json:"backend,omitempty"`
	// extra are the keys a newer sshr wrote, kept through every save
	extra map[string]json.RawMessage
}

// stateFormat is the format of state.json this build writes, a file
// without "version" is format 1, a newer one stops the sync
const stateFormat = 1

// rotation is a committed vault key change still to deliver, the key waits
// in the keychain under key-pending until every envelope is written
type rotation struct {
	Epoch   int                `json:"epoch"`
	Devices []syncproto.Device `json:"devices"`
}

// pushPlan is what one push writes besides the changed hosts, a plan is
// built again after every lost race, from the state the pull just brought
type pushPlan struct {
	// devices replaces the device list, nil keeps it
	devices []syncproto.Device
	// epoch and key start a new vault key, every host is sealed again
	epoch int
	key   []byte
	// rotation is saved together with the new manifest
	rotation *rotation
}

// Client syncs one Store
type Client struct {
	Store *hosts.Store
	// Dir holds state.json, ~/.sshr/sync
	Dir string
	// KeyPrefix names the keychain entries of this device, tests give two
	// clients different ones
	KeyPrefix string
	// AcceptReset lets a pull accept a server state older than the last one
	// seen, after a server restore from backup
	AcceptReset bool
	// Log gets one line per notable event
	Log  io.Writer
	HTTP *http.Client
	// Backend is the store the sync goes through, nil is sshr-sync over
	// HTTP at the server of the state
	Backend Backend
	// BackendRef and StoreSecret name the store Init and Join set up and
	// keep in the state and the keychain, OpenBackend opens it again on
	// later runs
	BackendRef  *BackendRef
	StoreSecret string
	OpenBackend func(ref BackendRef, secret string) (Backend, error)

	st   *state
	keys *deviceKeys
	// keyOK are the epochs whose key verified a manifest in this run
	keyOK map[int]bool
	// running is set while this Client holds the run lock, calls inside
	// the run do not take it again
	running bool
	// LeftOut names the hosts the last run did not sync and why, a run
	// that left hosts out still succeeds, the caller says so
	LeftOut map[string]string
}

// leaveOut notes a host the run did not sync
func (c *Client) leaveOut(id, why string) {
	if c.LeftOut == nil {
		c.LeftOut = map[string]string{}
	}
	c.LeftOut[id] = why
}

// run holds the lock of the sync folder for fn, two sync runs at once
// would load the same state, the last save would drop a key change of the
// other and both could store their own new vault key, the second run stops
// at once instead of waiting, the state is read again under the lock
func (c *Client) run(fn func() error) error {
	if c.running {
		return fn()
	}
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return err
	}
	unlock, err := fileio.WaitLock(filepath.Join(c.Dir, "run.lock"), "running a sync", 0)
	if err != nil {
		return err
	}
	defer unlock()
	c.running, c.st, c.LeftOut = true, nil, nil
	defer func() { c.running = false }()
	return fn()
}

// ErrKeyPending means the manifest uses a vault key whose envelope has not
// reached this device yet, the device that changed it delivers it shortly
var ErrKeyPending = errors.New("the device that changed the vault key has not delivered it here yet, sync again in a moment")

// applyLocked is called by apply with the host lock held, before the host
// is read again, tests use it to save a host from another Store meanwhile
var applyLocked func(id string)

// errLost means another device pushed first
var errLost = errors.New("other devices kept pushing at the same time, try again")

// ErrNotSetUp means sync init or sync join has not run on this machine
var ErrNotSetUp = errors.New("sync is not set up here, run sshr sync init or sshr sync join")

// DefaultDir is ~/.sshr/sync
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".sshr", "sync"), nil
}

func (c *Client) logf(format string, a ...any) {
	if c.Log != nil {
		fmt.Fprintf(c.Log, format+"\n", a...)
	}
}

func (c *Client) prefix() string {
	if c.KeyPrefix == "" {
		return "sync-"
	}
	return c.KeyPrefix
}

func (c *Client) statePath() string { return filepath.Join(c.Dir, "state.json") }

// errSetUp is the answer of init and join on a machine that already syncs
var errSetUp = errors.New("sync is already set up here, see sshr sync status")

// CheckFree fails when sync is already set up here, the CLI checks it
// before it asks for the secret of a store and writes a probe into it
func (c *Client) CheckFree() error {
	if _, err := os.Stat(c.statePath()); err == nil {
		return errSetUp
	}
	return nil
}

// SecretNames are the names of the secrets the sync of the default device
// keeps (its key seed, the vault keys of every epoch, a key change still
// to deliver), for moving them when the vault mode changes, a sync state
// that exists and does not read is an error, the names of older epochs
// would be missed
func SecretNames(dir string) ([]string, error) {
	names := []string{"sync-device", "sync-key-pending", "sync-store-secret"}
	b, err := fileio.ReadFileShared(filepath.Join(dir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return names, nil
	}
	if err != nil {
		return nil, err
	}
	var st struct {
		Epoch int `json:"epoch"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("the sync state does not read: %v", err)
	}
	for e := 1; e <= st.Epoch; e++ {
		names = append(names, "sync-key-"+strconv.Itoa(e))
	}
	return names, nil
}

func (c *Client) load() error {
	if c.st != nil {
		return nil
	}
	b, err := fileio.ReadFileShared(c.statePath())
	if os.IsNotExist(err) {
		return ErrNotSetUp
	}
	if err != nil {
		return err
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		if _, format, ferr := record.Extra(b, reflect.TypeOf(state{})); ferr == nil && format > stateFormat {
			return fmt.Errorf("%w: the sync state was written by a newer sshr (format %d), update sshr on this device to sync", record.ErrNewerFormat, format)
		}
		return fmt.Errorf("sync state %s is damaged: %v", c.statePath(), err)
	}
	var format int
	if st.extra, format, err = record.Extra(b, reflect.TypeOf(state{})); err != nil {
		return fmt.Errorf("sync state %s is damaged: %v", c.statePath(), err)
	}
	if format > stateFormat {
		// the state holds the counter and the head of the chain, a sync
		// that does not understand it all would break the history
		return fmt.Errorf("%w: the sync state was written by a newer sshr (format %d), update sshr on this device to sync", record.ErrNewerFormat, format)
	}
	if st.Entries == nil {
		st.Entries = map[string]entryState{}
	}
	seed, ok, err := vault.SecretGet(c.prefix() + "device")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("the device key of this machine is gone from the keychain, run sshr sync leave and join again")
	}
	if c.keys, err = newDeviceKeys(seed); err != nil {
		return err
	}
	c.st = &st
	if err := c.openBackend(); err != nil {
		c.st = nil
		return err
	}
	return nil
}

// save writes the state through a temp file, only after a sync is fully
// applied, a crash before it repeats the sync instead of skipping one
func (c *Client) save() error {
	b, err := json.MarshalIndent(c.st, "", "  ")
	if err == nil {
		b, err = record.AppendKeys(b, c.st.extra)
	}
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return err
	}
	return fileio.WriteFile(c.statePath(), b, 0o600)
}

// serverOf is the server of a new state: an sshr-sync address, or the
// name of the store of another Backend as it is
func (c *Client) serverOf(server string) (string, error) {
	if c.Backend != nil {
		return server, nil
	}
	return checkServer(server)
}

// checkServer refuses plain HTTP except to this machine
func checkServer(raw string) (string, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("bad server address %q", raw)
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", errors.New("the sync server must use https")
		}
	} else if u.Scheme != "https" {
		return "", fmt.Errorf("bad server address %q", raw)
	}
	return u.String(), nil
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: time.Minute}
}

// call sends one request to the account on the server
func (c *Client) call(method, path string, body []byte, hdr map[string]string) (int, []byte, http.Header, error) {
	u := c.st.Server + "/v1/accounts/" + c.st.Account + path
	if path == "" || strings.HasPrefix(path, "!") {
		u = c.st.Server + strings.TrimPrefix(path, "!")
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	if c.st.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.st.Token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("sync server: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, syncproto.MaxManifest*4))
	return resp.StatusCode, b, resp.Header, err
}

func serverError(code int, b []byte) error {
	var e struct{ Error string }
	if json.Unmarshal(b, &e) == nil && e.Error != "" {
		return fmt.Errorf("sync server: %s (%d)", e.Error, code)
	}
	return fmt.Errorf("sync server answered %d", code)
}

func (c *Client) self() syncproto.Device { return c.keys.device(c.st.Name) }

func (c *Client) vaultKey(epoch int) ([]byte, error) {
	name := c.prefix() + "key-" + strconv.Itoa(epoch)
	key, ok, err := vault.SecretGet(name)
	if err != nil {
		return nil, err
	}
	if ok {
		return key, nil
	}
	if c.st.Rotation != nil && c.st.Rotation.Epoch == epoch {
		if key, ok, err := vault.SecretGet(c.prefix() + "key-pending"); err != nil || ok {
			return key, err
		}
	}
	if key, err = c.envelopeKey(epoch); err != nil {
		return nil, err
	}
	return key, vault.SecretSet(name, key)
}

func (c *Client) markKey(epoch int) {
	if c.keyOK == nil {
		c.keyOK = map[int]bool{}
	}
	c.keyOK[epoch] = true
}

// checkKey makes sure key opens the current manifest before a push seals
// anything with it, a wrong key cached here would write a manifest no
// other device can verify, a wrong one is replaced by the envelope's key
func (c *Client) checkKey(epoch int, key []byte) ([]byte, error) {
	if c.keyOK[epoch] || c.st.Counter == 0 {
		return key, nil
	}
	_, b, err := c.backend().Head()
	if errors.Is(err, ErrNotFound) {
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	var sm syncproto.Signed
	var m syncproto.Manifest
	if err := json.Unmarshal(b, &sm); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(sm.Body, &m); err != nil {
		return nil, err
	}
	if m.Epoch != epoch {
		// another device changed the key meanwhile, the push loses the
		// race on the counter and pulls first
		return key, nil
	}
	if verifyMAC(&sm, key) != nil {
		fresh, err := c.envelopeKey(epoch)
		if err != nil {
			return nil, err
		}
		if err := verifyMAC(&sm, fresh); err != nil {
			return nil, fmt.Errorf("the vault key on this device does not open the account, pair it again: %v", err)
		}
		if err := vault.SecretSet(c.prefix()+"key-"+strconv.Itoa(epoch), fresh); err != nil {
			return nil, err
		}
		key = fresh
	}
	c.markKey(epoch)
	return key, nil
}

// envelopeKey reads the vault key of epoch from this device's envelope on
// the server, without touching the keychain
func (c *Client) envelopeKey(epoch int) ([]byte, error) {
	b, err := c.backend().GetEnvelope(c.st.DeviceID, epoch)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrKeyPending
	}
	if err != nil {
		return nil, err
	}
	var env syncproto.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, err
	}
	if env.Epoch < epoch {
		return nil, ErrKeyPending
	}
	if env.Epoch != epoch {
		return nil, fmt.Errorf("no vault key of epoch %d for this device, it may have been removed, re-pair it", epoch)
	}
	return c.keys.openEnvelope(env, c.st.Account)
}

// newSeed makes the device key of this machine
func (c *Client) newSeed() error {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	if err := vault.SecretSet(c.prefix()+"device", seed); err != nil {
		return err
	}
	var err error
	c.keys, err = newDeviceKeys(seed)
	return err
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "device"
	}
	if len(h) > 64 {
		h = h[:64]
	}
	return h
}

// Init creates an account on server with this machine as its first device
// and pushes the hosts
func (c *Client) Init(server, name string) error {
	return c.run(func() error { return c.initAccount(server, name) })
}

func (c *Client) initAccount(server, name string) error {
	if err := c.CheckFree(); err != nil {
		return err
	}
	srv, err := c.serverOf(server)
	if err != nil {
		return err
	}
	if name == "" {
		name = hostname()
	}
	if err := c.newSeed(); err != nil {
		return err
	}
	c.st = &state{Server: srv, Name: name, Entries: map[string]entryState{}}
	c.keepBackend()
	self := c.self()
	body, _ := json.Marshal(syncproto.NewAccountRequest{Device: self})
	b, err := c.backend().CreateAccount(body)
	if err != nil {
		return err
	}
	var tr syncproto.TokenResponse
	if err := json.Unmarshal(b, &tr); err != nil {
		return err
	}
	c.st.Account, c.st.Token, c.st.DeviceID, c.st.Epoch = tr.Account, tr.Token, self.ID, 1
	c.st.Trusted = []syncproto.Device{self}
	key := make([]byte, 32)
	rand.Read(key)
	if err := vault.SecretSet(c.prefix()+"key-1", key); err != nil {
		return err
	}
	if err := c.putEnvelope(self, 1, key); err != nil {
		return err
	}
	if err := c.saveNew(); err != nil {
		return err
	}
	return c.push(nil)
}

func (c *Client) putEnvelope(d syncproto.Device, epoch int, key []byte) error {
	env, err := sealEnvelope(d, c.st.Account, epoch, key)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(env)
	// a newer key already delivered to that device by a later rotation
	// stays, writing this one over it would lock the device out
	if err := c.backend().PutEnvelope(d.ID, b); err != nil && !errors.Is(err, ErrStaleEpoch) {
		return err
	}
	return nil
}

// Invite is the code another machine joins with, the account and the
// fingerprint of this device, which the new device will trust
func (c *Client) Invite() (string, error) {
	if err := c.load(); err != nil {
		return "", err
	}
	return c.st.Account + "." + strings.ReplaceAll(Fingerprint(c.self().SignPub), "-", ""), nil
}

// Join asks to add this machine to the account of code, an existing device
// approves it with sshr sync approve after comparing the fingerprint Join
// returns
func (c *Client) Join(server, code, name string) (out string, err error) {
	err = c.run(func() error {
		out, err = c.join(server, code, name)
		return err
	})
	return out, err
}

func (c *Client) join(server, code, name string) (string, error) {
	if err := c.CheckFree(); err != nil {
		return "", err
	}
	srv, err := c.serverOf(server)
	if err != nil {
		return "", err
	}
	account, approver, ok := strings.Cut(strings.TrimSpace(code), ".")
	if !ok || len(account) != 32 || len(approver) != 20 {
		return "", errors.New("bad invite code, it looks like <32 hex>.<20 hex>, from sshr sync invite")
	}
	if name == "" {
		name = hostname()
	}
	if err := c.newSeed(); err != nil {
		return "", err
	}
	c.st = &state{Server: srv, Account: account, Name: name, Approver: approver, Entries: map[string]entryState{}}
	c.keepBackend()
	self := c.self()
	body, _ := json.Marshal(syncproto.NewAccountRequest{Device: self})
	b, err := c.backend().Join(body)
	if err != nil {
		return "", err
	}
	var tr syncproto.TokenResponse
	if err := json.Unmarshal(b, &tr); err != nil {
		return "", err
	}
	// the account that took the device is the one of the invite, a store
	// or server that holds another is not joined
	if tr.Account != account {
		return "", fmt.Errorf("the sync store holds account %s, the invite is for %s, check the server or store", short(tr.Account, 8), short(account, 8))
	}
	c.st.Token, c.st.DeviceID = tr.Token, self.ID
	return Fingerprint(self.SignPub), c.saveNew()
}

// Pending lists devices that joined and wait for approval
func (c *Client) Pending() ([]syncproto.DeviceRecord, error) {
	if err := c.load(); err != nil {
		return nil, err
	}
	b, err := c.backend().Devices()
	if err != nil {
		return nil, err
	}
	var all []syncproto.DeviceRecord
	if err := json.Unmarshal(b, &all); err != nil {
		return nil, err
	}
	var out []syncproto.DeviceRecord
	for _, d := range all {
		if !d.Active && syncproto.DeviceID(d.SignPub) == d.ID {
			d.Name = CleanName(d.Name)
			out = append(out, d)
		}
	}
	return out, nil
}

// Approve adds a waiting device whose ID starts with prefix, call it only
// after the fingerprint matched the one on the new device's screen
func (c *Client) Approve(prefix string) (out *syncproto.DeviceRecord, err error) {
	err = c.run(func() error {
		out, err = c.approve(prefix)
		return err
	})
	return out, err
}

func (c *Client) approve(prefix string) (*syncproto.DeviceRecord, error) {
	pending, err := c.Pending()
	if err != nil {
		return nil, err
	}
	var found []syncproto.DeviceRecord
	for _, d := range pending {
		if strings.HasPrefix(d.ID, prefix) || strings.HasPrefix(strings.ReplaceAll(Fingerprint(d.SignPub), "-", ""), strings.ReplaceAll(prefix, "-", "")) {
			found = append(found, d)
		}
	}
	if len(found) != 1 {
		return nil, fmt.Errorf("%q matches %d waiting devices", prefix, len(found))
	}
	d := found[0]
	if err := c.Pull(); err != nil {
		return nil, err
	}
	// the list is taken from the state each attempt pulled, a device
	// another one removed meanwhile is not written back
	plan := func() (pushPlan, error) {
		for _, t := range c.st.Trusted {
			if t.ID == d.ID {
				return pushPlan{}, nil
			}
		}
		return pushPlan{devices: append(append([]syncproto.Device(nil), c.st.Trusted...), d.Device)}, nil
	}
	if err := c.push(plan); err != nil {
		return nil, err
	}
	// the envelope is sealed for the epoch that was committed, the device
	// cannot read anything before it is activated below
	key, err := c.vaultKey(c.st.Epoch)
	if err != nil {
		return nil, err
	}
	if err := c.putEnvelope(d.Device, c.st.Epoch, key); err != nil {
		return nil, err
	}
	if err := c.backend().Activate(d.ID); err != nil {
		return nil, err
	}
	return &d, nil
}

// payload is what one host looks like inside its encrypted blob, the saved
// password travels in the clear inside the encryption and is sealed again
// with the vault key of the receiving machine, a private key stored in sshr
// does not travel
type payload struct {
	Host     hosts.Host `json:"host"`
	Password string     `json:"password,omitempty"`
}

// payloadJSON is the payload on the wire, the host is written and read by
// app, which carries the fields of a newer sshr
type payloadJSON struct {
	Host     json.RawMessage `json:"host"`
	Password string          `json:"password,omitempty"`
}

func payloadOf(h hosts.Host) ([]byte, error) {
	p := payload{Host: h}
	p.Host.PasswordSealed, p.Host.PlainPassword, p.Host.KeySealed = "", "", ""
	// when this machine last connected stays here, it would make every
	// connect a change to push
	p.Host.LastConnected = nil
	// the save counter is per machine, Import sets its own
	p.Host.Rev = 0
	// references to secrets of this machine stay here, the other devices
	// do not take them anyway (hosts.FromOtherDevice)
	p.Host.PasswordRef, p.Host.KeyRef = "", ""
	// the host part first, a host this build does not send (a newer
	// format) is refused before its password is opened
	host, err := hosts.HostPayloadJSON(p.Host)
	if err != nil {
		return nil, err
	}
	// only a password saved in sshr is read, one in 1Password stays there
	if h.PasswordMode == hosts.PasswordSaved {
		if err := hosts.UnlockSaved(&h); err != nil {
			return nil, err
		}
		p.Password = h.Password
	}
	return json.Marshal(payloadJSON{Host: host, Password: p.Password})
}

// localHash is keyed with the device key, the state file holds it and must
// not let anyone guess a password by hashing candidates
func (c *Client) localHash(plain []byte) string {
	m := hmac.New(sha256.New, derive(c.keys.sign.Seed(), "local hash", 32))
	m.Write(plain)
	return hex.EncodeToString(m.Sum(nil))
}

func newer(a, b syncproto.Entry) bool {
	if a.Lamport != b.Lamport {
		return a.Lamport > b.Lamport
	}
	return a.Device > b.Device
}

// fetchHistory returns the manifests after the last one seen and checks
// that the server did not roll the account back
func (c *Client) fetchHistory() ([]syncproto.Signed, error) {
	var out []syncproto.Signed
	after := c.st.Counter
	// cut is the first change the sync no longer has when the history it
	// sends starts past what this device saw
	var cut uint64
	for {
		b, err := c.backend().ManifestsAfter(after)
		if errors.Is(err, ErrPending) {
			return nil, errors.New("this device still waits for approval, run sshr sync approve on a device that is already in")
		}
		if err != nil {
			return nil, err
		}
		var page []syncproto.Signed
		if err := json.Unmarshal(b, &page); err != nil {
			return nil, err
		}
		if len(page) == 0 {
			break
		}
		// every change follows the one before, a page that does not move
		// on would be asked for again and again, a device that joins may
		// start where the kept history starts
		for _, sm := range page {
			var m syncproto.Manifest
			if err := json.Unmarshal(sm.Body, &m); err != nil {
				return nil, err
			}
			joining := len(out) == 0 && after == 0 && c.st.Counter == 0 && c.st.Approver != ""
			switch {
			case m.Counter <= after:
				return nil, fmt.Errorf("the server sent change %d again after %d, the history does not add up", m.Counter, after)
			case m.Counter != after+1 && !joining && len(out) == 0 && after == c.st.Counter:
				// trimmed history or a gap, told apart once the length of
				// what follows is known
				cut = after + 1
			case m.Counter != after+1 && !joining:
				return nil, fmt.Errorf("the server skipped changes %d to %d, the history does not add up", after+1, m.Counter-1)
			}
			after = m.Counter
			out = append(out, sm)
		}
	}
	if cut > 0 {
		var m syncproto.Manifest
		json.Unmarshal(out[0].Body, &m)
		// a trim keeps keepHistory changes, a shorter history with a hole
		// is a server that hides changes, so is a long one whose last
		// change no trusted device signed, padding costs nothing
		last := out[len(out)-1]
		if len(out) >= keepHistory && verifySignature(&last, c.st.Trusted) == nil {
			return nil, fmt.Errorf("the sync keeps only the last %d changes and no longer has changes %d to %d, this device fell behind, run sshr sync leave and join again", keepHistory, cut, m.Counter-1)
		}
		return nil, fmt.Errorf("the server skipped changes %d to %d, the history does not add up", cut, m.Counter-1)
	}
	if len(out) == 0 && c.st.Counter > 0 {
		cur, _, err := c.backend().Head()
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if cur < c.st.Counter && !c.AcceptReset {
			return nil, fmt.Errorf("the server shows change %d, this device has seen %d, the server rolled the account back or lost data, run with --accept-reset only if the server was restored from a backup", cur, c.st.Counter)
		}
		if cur < c.st.Counter {
			c.st.Counter, c.st.Head = 0, ""
			return c.fetchHistory()
		}
	}
	return out, nil
}

// verify checks one manifest against what this device trusts and returns
// it, it then becomes the trusted state, the MAC is checked only when
// withMAC, the signature already vouches for a manifest in the middle of
// the chain and the server keeps the vault key of the newest epoch only
func (c *Client) verify(sm *syncproto.Signed, withMAC bool) (*syncproto.Manifest, error) {
	var m syncproto.Manifest
	if err := json.Unmarshal(sm.Body, &m); err != nil {
		return nil, err
	}
	if m.Account != c.st.Account {
		return nil, errors.New("manifest of another account")
	}
	if err := checkFormat(m.Version); err != nil {
		return nil, err
	}
	if c.st.Counter > 0 || c.st.Approver == "" {
		if m.Counter != c.st.Counter+1 {
			return nil, fmt.Errorf("the server skipped changes %d to %d, the history does not add up", c.st.Counter+1, m.Counter-1)
		}
		if m.Prev != c.st.Head {
			return nil, fmt.Errorf("change %d does not follow the last change this device saw, the server shows different histories to different devices", m.Counter)
		}
		if err := verifySignature(sm, c.st.Trusted); err != nil {
			return nil, err
		}
	} else {
		// a joined device trusts only the device that invited it
		var signer *syncproto.Device
		for i := range m.Devices {
			if m.Devices[i].ID == sm.Signer {
				signer = &m.Devices[i]
			}
		}
		if signer == nil || strings.ReplaceAll(Fingerprint(signer.SignPub), "-", "") != c.st.Approver {
			return nil, errors.New("the first manifest is not signed by the device that invited this one")
		}
		if err := verifySignature(sm, []syncproto.Device{*signer}); err != nil {
			return nil, err
		}
	}
	if m.Epoch < c.st.Epoch {
		return nil, errors.New("manifest of an old vault key epoch")
	}
	if withMAC {
		// a key change this device committed while its state was not
		// saved, its key still waits as key-pending and verifies the
		// manifest, the delivery is taken up again
		if c.st.Rotation == nil {
			if pending, ok, _ := vault.SecretGet(c.prefix() + "key-pending"); ok && verifyMAC(sm, pending) == nil {
				c.st.Rotation = &rotation{Epoch: m.Epoch, Devices: m.Devices}
			}
		}
		key, err := c.vaultKey(m.Epoch)
		if err != nil {
			return nil, err
		}
		if err := verifyMAC(sm, key); err != nil {
			// the key cached in the keychain may be a wrong one, the key
			// in the envelope replaces it only when it verifies, a failed
			// read leaves the cache as it was
			fresh, ferr := c.envelopeKey(m.Epoch)
			if ferr != nil || verifyMAC(sm, fresh) != nil {
				return nil, err
			}
			if err := vault.SecretSet(c.prefix()+"key-"+strconv.Itoa(m.Epoch), fresh); err != nil {
				return nil, err
			}
		}
		c.markKey(m.Epoch)
	}
	inside := false
	for _, d := range m.Devices {
		if syncproto.DeviceID(d.SignPub) != d.ID {
			return nil, errors.New("manifest lists a device whose id does not match its key")
		}
		inside = inside || d.ID == c.st.DeviceID
	}
	if !inside {
		return nil, errors.New("this device was removed from the account, run sshr sync leave")
	}
	c.st.Trusted, c.st.Head, c.st.Counter, c.st.Epoch = m.Devices, syncproto.BodyHash(sm.Body), m.Counter, m.Epoch
	c.st.Approver = ""
	return &m, nil
}

// checkFormat takes a manifest of this format or an older one, a field
// added to the manifest keeps the format, only a change older devices
// cannot read raises it, and then they are told to update instead of
// failing on a mismatch they cannot explain
func checkFormat(v int) error {
	switch {
	case v < 1:
		return fmt.Errorf("manifest of format %d, no sshr writes that", v)
	case v > syncproto.FormatVersion:
		return fmt.Errorf("the account was written by a newer sshr (format %d, this one reads up to %d), update sshr on this device", v, syncproto.FormatVersion)
	}
	return nil
}

// Pull applies the changes other devices pushed
func (c *Client) Pull() error {
	return c.run(func() error { return c.pull() })
}

func (c *Client) pull() error {
	if err := c.load(); err != nil {
		return err
	}
	if err := c.finishRotation(); err != nil {
		return err
	}
	history, err := c.fetchHistory()
	if err != nil {
		return err
	}
	if c.st.Approver != "" {
		// skip to the manifest that added this device, older ones were
		// made before it was trusted
		for i := range history {
			var m syncproto.Manifest
			if json.Unmarshal(history[i].Body, &m) == nil {
				for _, d := range m.Devices {
					if d.ID == c.st.DeviceID {
						history = history[i:]
						goto found
					}
				}
			}
		}
		return errors.New("no manifest adds this device yet, approve it on a device that is already in")
	found:
	}
	// a pull cut short keeps the chain where it was, so the next run
	// verifies and applies the same manifests again, the hosts applied so
	// far keep their entry state and are not taken for local edits
	before := *c.st
	rollback := func() {
		c.st.Counter, c.st.Head, c.st.Trusted, c.st.Epoch, c.st.Approver = before.Counter, before.Head, before.Trusted, before.Epoch, before.Approver
	}
	var last *syncproto.Manifest
	for i := range history {
		// a device offline through several key rotations can open only
		// the newest epoch, so only the manifest it applies needs the key
		if last, err = c.verify(&history[i], i == len(history)-1); err != nil {
			rollback()
			return err
		}
	}
	if last != nil {
		if err := c.apply(last); err != nil {
			rollback()
			if serr := c.save(); serr != nil {
				return serr
			}
			return err
		}
	}
	if err := c.finishRotation(); err != nil {
		return err
	}
	c.st.LastSync = time.Now().UTC()
	return c.save()
}

// apply writes the hosts of m that changed since the last sync, a host
// changed both here and there keeps the later change by (Lamport, device)
func (c *Client) apply(m *syncproto.Manifest) error {
	key, err := c.vaultKey(m.Epoch)
	if err != nil {
		return err
	}
	local, broken, err := c.localHosts()
	if err != nil {
		return err
	}
	if c.st.Skipped == nil {
		c.st.Skipped = map[string]syncproto.Entry{}
	}
	ids := make([]string, 0, len(m.Entries))
	for id := range m.Entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		e := m.Entries[id]
		if why, ok := broken[id]; ok {
			c.logf("skipped %s, %s", short(id, 8), why)
			c.leaveOut(id, why)
			continue
		}
		delete(c.st.Skipped, id)
		var dup *hosts.Host
		conflict := false
		known, seen := c.st.Entries[id]
		knownEntry := syncproto.Entry{Lamport: known.Lamport, Device: known.Device}
		if seen && e.Lamport == known.Lamport && e.Device == known.Device {
			if e.Hash != "" {
				known.Blob = e.Hash
				c.st.Entries[id] = known
			}
			continue
		}
		if seen && !newer(e, knownEntry) {
			continue
		}
		// the remote version is downloaded first, the local host is read
		// again right after, so an edit saved meanwhile in the app or the
		// CLI is seen and a failed download leaves nothing behind
		var p *payload
		if !e.Deleted {
			if p, err = c.fetchPayload(id, e, key, m.Epoch); errors.Is(err, errBadPayload) {
				// a payload this sshr cannot read (a newer field type) is
				// carried on and tried again on every pull, as a host Import
				// refuses is, the other hosts go on
				c.st.Skipped[id] = e
				c.logf("skipped %s: %v, it stays as it is here until this sshr can take it", short(id, 8), err)
				c.leaveOut(id, err.Error())
				continue
			} else if err != nil {
				return err
			}
		}
		// from reading the host here to writing the remote version no other
		// sshr process saves hosts, an edit saved before is seen as a local
		// change, one saved after waits and comes after the remote version
		err = c.Store.Locked(func(store *hosts.Store) error {
			if applyLocked != nil {
				applyLocked(id)
			}
			// the host as it is now, not as it was when the pull started, an
			// edit counts as a local change and goes through the conflict
			// rules instead of being overwritten
			if h, err := store.Find(id); err == nil && h.ID == id {
				if now, err := payloadOf(*h); err == nil {
					local[id] = now
				}
			} else if errors.Is(err, hosts.ErrNotFound) {
				delete(local, id)
			}
			if _, ok := local[id]; !ok && seen && !known.Deleted && !e.Deleted {
				// removed here and changed there, the change wins so nothing
				// written on the other device is lost, the user is told
				c.logf("%s was removed here and changed on device %s, it is back with that change, remove it again to drop it", short(id, 8), short(e.Device, 8))
			}
			if plain, ok := local[id]; ok && seen && c.localHash(plain) != known.Local {
				// neither side is lost, the later change keeps the host and
				// the other one becomes a copy that syncs like any host
				mine := syncproto.Entry{Lamport: known.Lamport + 1, Device: c.st.DeviceID}
				if newer(mine, e) {
					if !e.Deleted {
						p.Host.Password = p.Password
						p.Host.ID = ""
						p.Host.Name = conflictName(p.Host.Name, e.Device)
						var notes []string
						p.Host, notes = hosts.FromOtherDevice(p.Host, nil)
						cp, err := store.Add(p.Host)
						if err != nil {
							c.st.Skipped[id] = e
							c.logf("skipped %s: %v, it stays as it is here until this sshr can take it", p.Host.Name, err)
							c.leaveOut(id, err.Error())
							return nil
						}
						c.logf("conflict on %s: kept the change made here, the one from device %s is saved as %q", short(id, 8), short(e.Device, 8), cp.Name)
						for _, n := range notes {
							c.logf("%s: %s", cp.Name, n)
						}
					}
					// the remote version is handled, the entry moves to it
					// and keeps the old local hash, the change made here
					// still counts as not pushed and the next push outranks
					// the remote one, a later pull makes no second copy
					c.st.Entries[id] = entryState{Lamport: e.Lamport, Device: e.Device, Blob: e.Hash, Deleted: e.Deleted, Local: known.Local}
					return nil
				}
				conflict = true
			}
			next := entryState{Lamport: e.Lamport, Device: e.Device, Blob: e.Hash, Deleted: e.Deleted}
			if conflict {
				var name string
				if h, err := store.Find(id); err == nil {
					name = h.Name
				}
				cp, err := store.Duplicate(id, conflictName(name, c.st.DeviceID))
				if err != nil {
					return fmt.Errorf("keeping the local version of %s: %v", name, err)
				}
				dup = cp
			}
			if dup != nil && e.Deleted {
				c.logf("conflict on %s: the change from device %s won, the one made here is saved as %q", short(id, 8), short(e.Device, 8), dup.Name)
			}
			if e.Deleted {
				if _, ok := local[id]; ok {
					if err := store.Delete(id); err != nil && !errors.Is(err, hosts.ErrNotFound) {
						return err
					}
					c.logf("removed %s", short(id, 8))
				}
				c.st.Entries[id] = next
				return nil
			}
			p.Host.Password = p.Password
			var cur *hosts.Host
			if h, err := store.Find(id); err == nil && h.ID == id {
				cur = h
			}
			_, notes := hosts.FromOtherDevice(p.Host, cur)
			h, err := store.Import(p.Host)
			if err != nil {
				// one host this version cannot take must not stop the others,
				// the copy made for it goes too, the next pull makes it again
				if dup != nil {
					store.Delete(dup.ID)
				}
				c.st.Skipped[id] = e
				c.logf("skipped %s: %v, it stays as it is here until this sshr can take it", p.Host.Name, err)
				c.leaveOut(id, err.Error())
				return nil
			}
			if dup != nil {
				c.logf("conflict on %s: the change from device %s won, the one made here is saved as %q", short(id, 8), short(e.Device, 8), dup.Name)
			}
			for _, n := range notes {
				c.logf("%s: %s", h.Name, n)
			}
			written, err := payloadOf(*h)
			if err != nil {
				return err
			}
			next.Local = c.localHash(written)
			c.st.Entries[id] = next
			c.logf("updated %s", h.Name)
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// fetchBlob downloads the blob hash of entry id and opens it
func (c *Client) fetchBlob(id, hash string, key []byte, epoch int) ([]byte, error) {
	blob, err := c.backend().GetBlob(hash)
	if err != nil {
		return nil, err
	}
	if blobHash(blob) != hash {
		return nil, fmt.Errorf("blob of %s does not match its hash", short(id, 8))
	}
	return openEntry(key, c.st.Account, id, epoch, blob)
}

// putBlob seals the plain payload of entry id and uploads it
func (c *Client) putBlob(key []byte, id string, epoch int, plain []byte) (string, error) {
	blob, err := sealEntry(key, c.st.Account, id, epoch, plain)
	if err != nil {
		return "", err
	}
	h := blobHash(blob)
	if err := c.backend().PutBlob(h, blob); err != nil {
		return "", err
	}
	return h, nil
}

// fetchPayload downloads and opens the blob of entry id
// errBadPayload is a payload that opens but does not read as a host, a
// download that fails or a blob that does not open is another error
var errBadPayload = errors.New("bad payload")

func (c *Client) fetchPayload(id string, e syncproto.Entry, key []byte, epoch int) (*payload, error) {
	plain, err := c.fetchBlob(id, e.Hash, key, epoch)
	if err != nil {
		return nil, err
	}
	var wire payloadJSON
	if err := json.Unmarshal(plain, &wire); err != nil {
		return nil, fmt.Errorf("%w: entry %s: %v", errBadPayload, short(id, 8), err)
	}
	host, err := hosts.HostFromPayloadJSON(wire.Host)
	if err != nil {
		return nil, fmt.Errorf("%w: entry %s: %v", errBadPayload, short(id, 8), err)
	}
	p := payload{Host: host, Password: wire.Password}
	if p.Host.ID != id {
		return nil, fmt.Errorf("%w: entry %s holds host %q", errBadPayload, short(id, 8), short(p.Host.ID, 40))
	}
	return &p, nil
}

// short cuts s to n characters for logs and names, ids from a manifest are
// signed but their length is not checked
func short(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// conflictName names the copy that keeps the losing side of a conflict
func conflictName(name, device string) string {
	return fmt.Sprintf("%s (conflict %s %s)", name, short(device, 6), time.Now().Format("2006-01-02 15:04"))
}

// localHosts returns the payload of every host here and the IDs of host
// files that do not load, those are neither deleted nor overwritten
func (c *Client) localHosts() (map[string][]byte, map[string]string, error) {
	list, unreadable, err := c.Store.ListAll()
	if err != nil {
		return nil, nil, err
	}
	// broken names the hosts that cannot sync from here and why, one host
	// whose file does not load or whose password does not open must not
	// stop the others, and must not be taken for a deleted one
	broken := map[string]string{}
	for _, id := range unreadable {
		broken[id] = "its host file " + id + ".json here does not load, fix it, removing it deletes the host on every device"
	}
	out := map[string][]byte{}
	for _, h := range list {
		p, err := payloadOf(h)
		if errors.Is(err, record.ErrNewerFormat) {
			broken[h.ID] = err.Error()
			continue
		}
		if err != nil {
			broken[h.ID] = err.Error() + ", it does not sync from here until then"
			continue
		}
		out[h.ID] = p
	}
	return out, broken, nil
}

// Push sends the hosts changed here, it pulls first
func (c *Client) Push() error {
	return c.run(func() error { return c.pushAll() })
}

func (c *Client) pushAll() error {
	if err := c.load(); err != nil {
		return err
	}
	return c.push(nil)
}

// push uploads changed hosts and a new manifest, plan says what else the
// manifest changes (approve, remove), nil changes nothing else, a push that
// loses the race to another device pulls and builds the plan again
func (c *Client) push(plan func() (pushPlan, error)) error {
	for try := 0; try < 5; try++ {
		if c.st.Counter > 0 {
			if err := c.Pull(); err != nil {
				return err
			}
		}
		var p pushPlan
		if plan != nil {
			var err error
			if p, err = plan(); err != nil {
				return err
			}
		}
		done, err := c.pushOnce(p)
		if err != nil || done {
			return err
		}
	}
	return errLost
}

// pushOnce writes one manifest, it returns false when another device
// pushed first, the state of this device changes only when it wins
func (c *Client) pushOnce(plan pushPlan) (bool, error) {
	devices, epoch, key := plan.devices, c.st.Epoch, plan.key
	reseal := plan.epoch != 0 && plan.epoch != c.st.Epoch
	if reseal {
		epoch = plan.epoch
	} else {
		var err error
		if key, err = c.vaultKey(epoch); err != nil {
			return false, err
		}
		if key, err = c.checkKey(epoch, key); err != nil {
			return false, err
		}
	}
	local, broken, err := c.localHosts()
	if err != nil {
		return false, err
	}
	entries := map[string]syncproto.Entry{}
	next := map[string]entryState{}
	for id, e := range c.st.Entries {
		entries[id] = syncproto.Entry{Hash: e.Blob, Lamport: e.Lamport, Device: e.Device, Deleted: e.Deleted}
		next[id] = e
	}
	// a skipped entry goes on as the other device wrote it, the host here
	// is neither pushed over it nor deleted
	for id, e := range c.st.Skipped {
		entries[id] = e
	}
	changed := devices != nil || c.st.Counter == 0
	fresh := map[string]bool{}
	for id, plain := range local {
		if _, ok := c.st.Skipped[id]; ok {
			continue
		}
		known, seen := c.st.Entries[id]
		lh := c.localHash(plain)
		unchanged := seen && !known.Deleted && known.Local == lh
		if unchanged && !reseal {
			continue
		}
		h, err := c.putBlob(key, id, epoch, plain)
		if err != nil {
			return false, err
		}
		fresh[id] = true
		if unchanged {
			// only the key changed, the stamp stays, so a device with its
			// own edit of this host sees no change from here
			entries[id] = syncproto.Entry{Hash: h, Lamport: known.Lamport, Device: known.Device}
			known.Blob = h
			next[id] = known
			changed = true
			continue
		}
		e := syncproto.Entry{Hash: h, Lamport: known.Lamport + 1, Device: c.st.DeviceID}
		entries[id] = e
		next[id] = entryState{Lamport: e.Lamport, Device: e.Device, Blob: h, Local: lh}
		changed = true
	}
	for id, known := range c.st.Entries {
		if _, ok := c.st.Skipped[id]; ok {
			continue
		}
		if why, ok := broken[id]; ok {
			c.logf("kept %s on other devices, %s", short(id, 8), why)
			c.leaveOut(id, why)
			continue
		}
		if _, ok := local[id]; !ok && !known.Deleted {
			e := syncproto.Entry{Lamport: known.Lamport + 1, Device: c.st.DeviceID, Deleted: true}
			entries[id] = e
			next[id] = entryState{Lamport: e.Lamport, Device: e.Device, Deleted: true}
			changed = true
		}
	}
	skipped := map[string]syncproto.Entry{}
	for id, e := range c.st.Skipped {
		skipped[id] = e
	}
	if reseal {
		// an entry carried on without a host here to seal (skipped, or a
		// file that does not load) is opened with the old key and sealed
		// with the new one, a device with the new key only reads it too
		oldKey, err := c.vaultKey(c.st.Epoch)
		if err != nil {
			return false, err
		}
		for id, e := range entries {
			if e.Deleted || fresh[id] {
				continue
			}
			plain, err := c.fetchBlob(id, e.Hash, oldKey, c.st.Epoch)
			if err != nil {
				return false, err
			}
			h, err := c.putBlob(key, id, epoch, plain)
			if err != nil {
				return false, err
			}
			if st, ok := next[id]; ok && st.Blob == e.Hash {
				st.Blob = h
				next[id] = st
			}
			if sk, ok := skipped[id]; ok {
				sk.Hash = h
				skipped[id] = sk
			}
			e.Hash = h
			entries[id] = e
		}
	}
	if !changed {
		return true, nil
	}
	if devices == nil {
		devices = c.st.Trusted
	}
	m := &syncproto.Manifest{
		Version: syncproto.FormatVersion, Account: c.st.Account, Epoch: epoch,
		Counter: c.st.Counter + 1, Prev: c.st.Head, Devices: devices, Entries: entries,
	}
	b, sm, err := c.keys.signManifest(m, key, c.st.DeviceID)
	if err != nil {
		return false, err
	}
	err = c.backend().PutManifest(c.st.Counter, b)
	if errors.Is(err, ErrCASLost) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	c.st.Counter, c.st.Head, c.st.Trusted, c.st.Entries = m.Counter, syncproto.BodyHash(sm.Body), devices, next
	c.st.Epoch, c.st.Skipped = epoch, skipped
	if plan.rotation != nil {
		c.st.Rotation = plan.rotation
	}
	c.st.LastSync = time.Now().UTC()
	return true, c.save()
}

// RemoveDevice takes a device out of the account, the vault key changes,
// every host is encrypted again with the new one and the device's token is
// revoked, what it already downloaded it keeps
//
// The token is revoked first, then nothing else changes before the new
// manifest wins: the new key waits in the keychain as key-pending, the
// envelopes of the kept devices are written only after the commit, a push
// that loses the race leaves nothing behind and the next attempt plans
// again from the pulled state
func (c *Client) RemoveDevice(prefix string) (out *syncproto.Device, err error) {
	err = c.run(func() error {
		out, err = c.removeDevice(prefix)
		return err
	})
	return out, err
}

func (c *Client) removeDevice(prefix string) (*syncproto.Device, error) {
	if err := c.Pull(); err != nil {
		return nil, err
	}
	target, _, err := c.matchDevice(prefix)
	if err != nil {
		return nil, err
	}
	if target == nil {
		return nil, fmt.Errorf("no other device matches %q", prefix)
	}
	removed := *target
	// the token goes first, a removed device that can still push could
	// block the others with manifests no one trusts, a rerun after a lost
	// race finds the device still listed and gets 404 here
	if err := c.backend().RemoveDevice(removed.ID); err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	gone := false
	plan := func() (pushPlan, error) {
		target, keep, err := c.matchDevice(removed.ID)
		if err != nil {
			return pushPlan{}, err
		}
		if target == nil {
			// another device removed it while this one retried
			gone = true
			return pushPlan{}, nil
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return pushPlan{}, err
		}
		if err := vault.SecretSet(c.prefix()+"key-pending", key); err != nil {
			return pushPlan{}, err
		}
		epoch := c.st.Epoch + 1
		return pushPlan{devices: keep, epoch: epoch, key: key, rotation: &rotation{Epoch: epoch, Devices: keep}}, nil
	}
	if err := c.push(plan); err != nil {
		if c.st.Rotation == nil {
			vault.SecretDelete(c.prefix() + "key-pending")
		}
		return nil, fmt.Errorf("the token of the device is revoked, it is still listed, run sshr sync remove-device again: %v", err)
	}
	if gone {
		return &removed, nil
	}
	if err := c.finishRotation(); err != nil {
		return nil, fmt.Errorf("the device is out of the account, the new key is not delivered to every device yet, run sshr sync again: %v", err)
	}
	return &removed, nil
}

// CleanName drops control and format characters from a device name, the
// name comes from whoever joined and must not move the cursor or recolor
// the fingerprint printed next to it
func CleanName(name string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, name)
}

// matchDevice finds the one other trusted device whose ID or fingerprint
// starts with prefix, and the devices that stay without it
func (c *Client) matchDevice(prefix string) (*syncproto.Device, []syncproto.Device, error) {
	var target *syncproto.Device
	var keep []syncproto.Device
	for i, d := range c.st.Trusted {
		if d.ID != c.st.DeviceID && prefix != "" && (strings.HasPrefix(d.ID, prefix) || strings.HasPrefix(strings.ReplaceAll(Fingerprint(d.SignPub), "-", ""), strings.ReplaceAll(prefix, "-", ""))) {
			if target != nil {
				return nil, nil, fmt.Errorf("%q matches several devices", prefix)
			}
			t := c.st.Trusted[i]
			t.Name = CleanName(t.Name)
			target = &t
			continue
		}
		keep = append(keep, d)
	}
	return target, keep, nil
}

// finishRotation delivers a committed vault key to every kept device and
// moves it from key-pending to the name of its epoch, it runs again on the
// next sync when it was cut short
func (c *Client) finishRotation() error {
	r := c.st.Rotation
	if r == nil {
		return nil
	}
	key, ok, err := vault.SecretGet(c.prefix() + "key-pending")
	if err != nil {
		return err
	}
	if !ok {
		if key, ok, err = vault.SecretGet(c.prefix() + "key-" + strconv.Itoa(r.Epoch)); err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("the key of epoch %d is lost on this device, remove and pair the other devices again", r.Epoch)
		}
	}
	if err := vault.SecretSet(c.prefix()+"key-"+strconv.Itoa(r.Epoch), key); err != nil {
		return err
	}
	for _, d := range r.Devices {
		if err := c.putEnvelope(d, r.Epoch, key); err != nil {
			return err
		}
	}
	vault.SecretDelete(c.prefix() + "key-pending")
	c.st.Rotation = nil
	return c.save()
}

// Status describes the sync state of this machine
type Status struct {
	Server, Account, Device, Name string
	Fingerprint                   string
	Counter                       uint64
	// State is the first hex of the hash of the last verified manifest,
	// equal on two devices means they see the same history
	State    string
	Devices  []syncproto.Device
	Waiting  bool
	LastSync time.Time
	// Backend is the store of an account that is not sshr-sync
	Backend *BackendRef
}

func (c *Client) Status() (*Status, error) {
	if err := c.load(); err != nil {
		return nil, err
	}
	st := &Status{
		Server: c.st.Server, Account: c.st.Account, Device: c.st.DeviceID, Name: c.st.Name,
		Fingerprint: Fingerprint(c.self().SignPub), Counter: c.st.Counter,
		Waiting: c.st.Approver != "", LastSync: c.st.LastSync, Backend: c.st.Backend,
	}
	for _, d := range c.st.Trusted {
		d.Name = CleanName(d.Name)
		st.Devices = append(st.Devices, d)
	}
	st.State = short(c.st.Head, 8)
	return st, nil
}

// Leave forgets sync on this machine, the hosts stay, the account and the
// other devices are not touched
func (c *Client) Leave(force bool) error {
	return c.run(func() error { return c.leave(force) })
}

func (c *Client) leave(force bool) error {
	b, err := fileio.ReadFileShared(c.statePath())
	if err == nil {
		var st state
		if json.Unmarshal(b, &st) == nil {
			// a key change this device committed but did not deliver yet
			// lives only here, leaving would strand the other devices
			if st.Rotation != nil && !force {
				if err := c.load(); err != nil {
					// only a store that will not open again asks for
					// --force, a keychain that fails for now does not
					var se storeOpenError
					if errors.As(err, &se) {
						return fmt.Errorf("the other devices still wait for the vault key this device changed and the sync store does not open to deliver it, leave with --force and pair them again: %v", err)
					}
					return err
				}
				if err := c.finishRotation(); err != nil {
					return fmt.Errorf("the other devices still wait for the vault key this device changed and it cannot be delivered now, run sshr sync again, or leave with --force and pair them again: %v", err)
				}
			}
			for e := 1; e <= st.Epoch; e++ {
				vault.SecretDelete(c.prefix() + "key-" + strconv.Itoa(e))
			}
		}
	}
	vault.SecretDelete(c.prefix() + "key-pending")
	vault.SecretDelete(c.prefix() + "device")
	vault.SecretDelete(c.storeSecretName())
	if err := os.Remove(c.statePath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	c.st = nil
	return nil
}
