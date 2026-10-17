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
	"sort"
	"strconv"
	"strings"
	"time"

	"sshr.dev/internal/app"
	"sshr.dev/internal/syncproto"
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
	LastSync time.Time             `json:"last_sync"`
}

// Client syncs one Store
type Client struct {
	Store *app.Store
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

	st   *state
	keys *deviceKeys
}

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

func (c *Client) load() error {
	if c.st != nil {
		return nil
	}
	b, err := os.ReadFile(c.statePath())
	if os.IsNotExist(err) {
		return ErrNotSetUp
	}
	if err != nil {
		return err
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("sync state %s is damaged: %v", c.statePath(), err)
	}
	if st.Entries == nil {
		st.Entries = map[string]entryState{}
	}
	seed, ok, err := app.SecretGet(c.prefix() + "device")
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
	return nil
}

// save writes the state through a temp file, only after a sync is fully
// applied, a crash before it repeats the sync instead of skipping one
func (c *Client) save() error {
	b, err := json.MarshalIndent(c.st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return err
	}
	tmp := c.statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.statePath())
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
	key, ok, err := app.SecretGet(name)
	if err != nil {
		return nil, err
	}
	if ok {
		return key, nil
	}
	code, b, _, err := c.call("GET", "/envelopes/"+c.st.DeviceID, nil, nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, serverError(code, b)
	}
	var env syncproto.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, err
	}
	if env.Epoch != epoch {
		return nil, fmt.Errorf("no vault key of epoch %d for this device, it may have been removed, re-pair it", epoch)
	}
	if key, err = c.keys.openEnvelope(env, c.st.Account); err != nil {
		return nil, err
	}
	return key, app.SecretSet(name, key)
}

// newSeed makes the device key of this machine
func (c *Client) newSeed() error {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	if err := app.SecretSet(c.prefix()+"device", seed); err != nil {
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
	if _, err := os.Stat(c.statePath()); err == nil {
		return errors.New("sync is already set up here, see sshr sync status")
	}
	srv, err := checkServer(server)
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
	self := c.self()
	body, _ := json.Marshal(syncproto.NewAccountRequest{Device: self})
	code, b, _, err := c.call("POST", "!/v1/accounts", body, nil)
	if err != nil {
		return err
	}
	if code != http.StatusCreated {
		return serverError(code, b)
	}
	var tr syncproto.TokenResponse
	if err := json.Unmarshal(b, &tr); err != nil {
		return err
	}
	c.st.Account, c.st.Token, c.st.DeviceID, c.st.Epoch = tr.Account, tr.Token, self.ID, 1
	c.st.Trusted = []syncproto.Device{self}
	key := make([]byte, 32)
	rand.Read(key)
	if err := app.SecretSet(c.prefix()+"key-1", key); err != nil {
		return err
	}
	if err := c.putEnvelope(self, 1, key); err != nil {
		return err
	}
	if err := c.save(); err != nil {
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
	code, rb, _, err := c.call("PUT", "/envelopes/"+d.ID, b, nil)
	if err != nil {
		return err
	}
	if code != http.StatusNoContent {
		return serverError(code, rb)
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
func (c *Client) Join(server, code, name string) (string, error) {
	if _, err := os.Stat(c.statePath()); err == nil {
		return "", errors.New("sync is already set up here, see sshr sync status")
	}
	srv, err := checkServer(server)
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
	self := c.self()
	body, _ := json.Marshal(syncproto.NewAccountRequest{Device: self})
	rc, b, _, err := c.call("POST", "/join", body, nil)
	if err != nil {
		return "", err
	}
	if rc != http.StatusCreated {
		return "", serverError(rc, b)
	}
	var tr syncproto.TokenResponse
	if err := json.Unmarshal(b, &tr); err != nil {
		return "", err
	}
	c.st.Token, c.st.DeviceID = tr.Token, self.ID
	return Fingerprint(self.SignPub), c.save()
}

// Pending lists devices that joined and wait for approval
func (c *Client) Pending() ([]syncproto.DeviceRecord, error) {
	if err := c.load(); err != nil {
		return nil, err
	}
	code, b, _, err := c.call("GET", "/devices", nil, nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, serverError(code, b)
	}
	var all []syncproto.DeviceRecord
	if err := json.Unmarshal(b, &all); err != nil {
		return nil, err
	}
	var out []syncproto.DeviceRecord
	for _, d := range all {
		if !d.Active && syncproto.DeviceID(d.SignPub) == d.ID {
			out = append(out, d)
		}
	}
	return out, nil
}

// Approve adds a waiting device whose ID starts with prefix, call it only
// after the fingerprint matched the one on the new device's screen
func (c *Client) Approve(prefix string) (*syncproto.DeviceRecord, error) {
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
	key, err := c.vaultKey(c.st.Epoch)
	if err != nil {
		return nil, err
	}
	if err := c.putEnvelope(d.Device, c.st.Epoch, key); err != nil {
		return nil, err
	}
	devices := append(append([]syncproto.Device(nil), c.st.Trusted...), d.Device)
	if err := c.push(devices); err != nil {
		return nil, err
	}
	code, b, _, err := c.call("POST", "/devices/"+d.ID+"/activate", nil, nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusNoContent {
		return nil, serverError(code, b)
	}
	return &d, nil
}

// payload is what one host looks like inside its encrypted blob, the saved
// password travels in the clear inside the encryption and is sealed again
// with the vault key of the receiving machine, a private key stored in sshr
// does not travel
type payload struct {
	Host     app.Host `json:"host"`
	Password string   `json:"password,omitempty"`
}

func payloadOf(h app.Host) ([]byte, error) {
	p := payload{Host: h}
	// only a password saved in sshr is read, one in 1Password stays there
	if h.PasswordMode == app.PasswordSaved {
		if err := app.Unlock(&h); err != nil {
			return nil, err
		}
		p.Password = h.Password
	}
	p.Host.PasswordSealed, p.Host.PlainPassword, p.Host.KeySealed = "", "", ""
	// references to secrets of this machine stay here, the other devices
	// do not take them anyway (app.FromOtherDevice)
	p.Host.PasswordRef, p.Host.KeyRef = "", ""
	return json.Marshal(p)
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
	for {
		code, b, _, err := c.call("GET", "/manifests?after="+strconv.FormatUint(after, 10), nil, nil)
		if err != nil {
			return nil, err
		}
		if code == http.StatusForbidden {
			return nil, errors.New("this device still waits for approval, run sshr sync approve on a device that is already in")
		}
		if code != http.StatusOK {
			return nil, serverError(code, b)
		}
		var page []syncproto.Signed
		if err := json.Unmarshal(b, &page); err != nil {
			return nil, err
		}
		if len(page) == 0 {
			break
		}
		out = append(out, page...)
		var m syncproto.Manifest
		if err := json.Unmarshal(page[len(page)-1].Body, &m); err != nil {
			return nil, err
		}
		after = m.Counter
	}
	if len(out) == 0 && c.st.Counter > 0 {
		code, b, hdr, err := c.call("GET", "/manifest", nil, nil)
		if err != nil {
			return nil, err
		}
		cur := uint64(0)
		if code == http.StatusOK {
			cur, _ = strconv.ParseUint(hdr.Get("ETag"), 10, 64)
		} else if code != http.StatusNotFound {
			return nil, serverError(code, b)
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
// it, it then becomes the trusted state
func (c *Client) verify(sm *syncproto.Signed) (*syncproto.Manifest, error) {
	var m syncproto.Manifest
	if err := json.Unmarshal(sm.Body, &m); err != nil {
		return nil, err
	}
	if m.Version != syncproto.FormatVersion || m.Account != c.st.Account {
		return nil, errors.New("manifest of another account or format")
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
	key, err := c.vaultKey(m.Epoch)
	if err != nil {
		return nil, err
	}
	if err := verifyMAC(sm, key); err != nil {
		return nil, err
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

// Pull applies the changes other devices pushed
func (c *Client) Pull() error {
	if err := c.load(); err != nil {
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
	var last *syncproto.Manifest
	for i := range history {
		if last, err = c.verify(&history[i]); err != nil {
			return err
		}
	}
	if last != nil {
		if err := c.apply(last); err != nil {
			return err
		}
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
	local, err := c.localHosts()
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(m.Entries))
	for id := range m.Entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		e := m.Entries[id]
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
		if plain, ok := local[id]; ok && seen && c.localHash(plain) != known.Local {
			// neither side is lost, the later change keeps the host and
			// the other one becomes a copy that syncs like any host
			mine := syncproto.Entry{Lamport: known.Lamport + 1, Device: c.st.DeviceID}
			if newer(mine, e) {
				if !e.Deleted {
					p, err := c.fetchPayload(id, e, key, m.Epoch)
					if err != nil {
						return err
					}
					p.Host.Password = p.Password
					p.Host.ID = ""
					p.Host.Name = conflictName(p.Host.Name, e.Device)
					var notes []string
					p.Host, notes = app.FromOtherDevice(p.Host, nil)
					cp, err := c.Store.Add(p.Host)
					if err != nil {
						return fmt.Errorf("keeping the other version of %s: %v", p.Host.Name, err)
					}
					c.logf("conflict on %s: kept the change made here, the one from device %s is saved as %q", id[:8], e.Device[:8], cp.Name)
					for _, n := range notes {
						c.logf("%s: %s", cp.Name, n)
					}
				}
				// the remote version is handled, the entry moves to it
				// and keeps the old local hash, the change made here
				// still counts as not pushed and the next push outranks
				// the remote one, a later pull makes no second copy
				c.st.Entries[id] = entryState{Lamport: e.Lamport, Device: e.Device, Blob: e.Hash, Deleted: e.Deleted, Local: known.Local}
				continue
			}
			var name string
			if h, err := c.Store.Find(id); err == nil {
				name = h.Name
			}
			cp, err := c.Store.Duplicate(id, conflictName(name, c.st.DeviceID))
			if err != nil {
				return fmt.Errorf("keeping the local version of %s: %v", name, err)
			}
			c.logf("conflict on %s: the change from device %s won, the one made here is saved as %q", id[:8], e.Device[:8], cp.Name)
		}
		next := entryState{Lamport: e.Lamport, Device: e.Device, Blob: e.Hash, Deleted: e.Deleted}
		if e.Deleted {
			if _, ok := local[id]; ok {
				if err := c.Store.Delete(id); err != nil && !errors.Is(err, app.ErrNotFound) {
					return err
				}
				c.logf("removed %s", id[:8])
			}
			c.st.Entries[id] = next
			continue
		}
		p, err := c.fetchPayload(id, e, key, m.Epoch)
		if err != nil {
			return err
		}
		p.Host.Password = p.Password
		var cur *app.Host
		if h, err := c.Store.Find(id); err == nil && h.ID == id {
			cur = h
		}
		_, notes := app.FromOtherDevice(p.Host, cur)
		h, err := c.Store.Import(p.Host)
		if err != nil {
			return fmt.Errorf("host %s: %v", p.Host.Name, err)
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
	}
	return nil
}

// fetchPayload downloads and opens the blob of entry id
func (c *Client) fetchPayload(id string, e syncproto.Entry, key []byte, epoch int) (*payload, error) {
	code, blob, _, err := c.call("GET", "/blobs/"+e.Hash, nil, nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, serverError(code, blob)
	}
	if blobHash(blob) != e.Hash {
		return nil, fmt.Errorf("blob of %s does not match its hash", id[:8])
	}
	plain, err := openEntry(key, c.st.Account, id, epoch, blob)
	if err != nil {
		return nil, err
	}
	var p payload
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, fmt.Errorf("entry %s: %v", id[:8], err)
	}
	if p.Host.ID != id {
		return nil, fmt.Errorf("entry %s holds host %s", id[:8], p.Host.ID)
	}
	return &p, nil
}

// conflictName names the copy that keeps the losing side of a conflict
func conflictName(name, device string) string {
	return fmt.Sprintf("%s (conflict %s %s)", name, device[:6], time.Now().Format("2006-01-02 15:04"))
}

func (c *Client) localHosts() (map[string][]byte, error) {
	hosts, err := c.Store.List()
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, h := range hosts {
		p, err := payloadOf(h)
		if err != nil {
			return nil, fmt.Errorf("host %s: %v", h.Name, err)
		}
		out[h.ID] = p
	}
	return out, nil
}

// Push sends the hosts changed here, it pulls first
func (c *Client) Push() error {
	if err := c.load(); err != nil {
		return err
	}
	return c.push(nil)
}

// push uploads changed hosts and a new manifest, devices replaces the
// device list (approve, remove), a push that loses the race to another
// device pulls and tries again
func (c *Client) push(devices []syncproto.Device) error {
	for try := 0; try < 5; try++ {
		if c.st.Counter > 0 {
			if err := c.Pull(); err != nil {
				return err
			}
		}
		done, err := c.pushOnce(devices)
		if err != nil || done {
			return err
		}
	}
	return errors.New("other devices kept pushing at the same time, try again")
}

func (c *Client) pushOnce(devices []syncproto.Device) (bool, error) {
	key, err := c.vaultKey(c.st.Epoch)
	if err != nil {
		return false, err
	}
	local, err := c.localHosts()
	if err != nil {
		return false, err
	}
	entries := map[string]syncproto.Entry{}
	next := map[string]entryState{}
	for id, e := range c.st.Entries {
		entries[id] = syncproto.Entry{Hash: e.Blob, Lamport: e.Lamport, Device: e.Device, Deleted: e.Deleted}
		next[id] = e
	}
	changed := devices != nil || c.st.Counter == 0
	for id, plain := range local {
		known, seen := c.st.Entries[id]
		lh := c.localHash(plain)
		if seen && !known.Deleted && known.Local == lh {
			continue
		}
		blob, err := sealEntry(key, c.st.Account, id, c.st.Epoch, plain)
		if err != nil {
			return false, err
		}
		h := blobHash(blob)
		code, b, _, err := c.call("PUT", "/blobs/"+h, blob, nil)
		if err != nil {
			return false, err
		}
		if code != http.StatusNoContent {
			return false, serverError(code, b)
		}
		e := syncproto.Entry{Hash: h, Lamport: known.Lamport + 1, Device: c.st.DeviceID}
		entries[id] = e
		next[id] = entryState{Lamport: e.Lamport, Device: e.Device, Blob: h, Local: lh}
		changed = true
	}
	for id, known := range c.st.Entries {
		if _, ok := local[id]; !ok && !known.Deleted {
			e := syncproto.Entry{Lamport: known.Lamport + 1, Device: c.st.DeviceID, Deleted: true}
			entries[id] = e
			next[id] = entryState{Lamport: e.Lamport, Device: e.Device, Deleted: true}
			changed = true
		}
	}
	if !changed {
		return true, nil
	}
	if devices == nil {
		devices = c.st.Trusted
	}
	m := &syncproto.Manifest{
		Version: syncproto.FormatVersion, Account: c.st.Account, Epoch: c.st.Epoch,
		Counter: c.st.Counter + 1, Prev: c.st.Head, Devices: devices, Entries: entries,
	}
	b, sm, err := c.keys.signManifest(m, key, c.st.DeviceID)
	if err != nil {
		return false, err
	}
	code, rb, _, err := c.call("PUT", "/manifest", b, map[string]string{"If-Match": strconv.FormatUint(c.st.Counter, 10)})
	if err != nil {
		return false, err
	}
	if code == http.StatusPreconditionFailed {
		return false, nil
	}
	if code != http.StatusNoContent {
		return false, serverError(code, rb)
	}
	c.st.Counter, c.st.Head, c.st.Trusted, c.st.Entries = m.Counter, syncproto.BodyHash(sm.Body), devices, next
	c.st.LastSync = time.Now().UTC()
	return true, c.save()
}

// RemoveDevice takes a device out of the account, the vault key changes,
// every host is encrypted again with the new one and the device's token is
// revoked, what it already downloaded it keeps
func (c *Client) RemoveDevice(prefix string) (*syncproto.Device, error) {
	if err := c.Pull(); err != nil {
		return nil, err
	}
	var target *syncproto.Device
	var keep []syncproto.Device
	for i, d := range c.st.Trusted {
		if d.ID != c.st.DeviceID && prefix != "" && (strings.HasPrefix(d.ID, prefix) || strings.HasPrefix(strings.ReplaceAll(Fingerprint(d.SignPub), "-", ""), strings.ReplaceAll(prefix, "-", ""))) {
			if target != nil {
				return nil, fmt.Errorf("%q matches several devices", prefix)
			}
			target = &c.st.Trusted[i]
			continue
		}
		keep = append(keep, d)
	}
	if target == nil {
		return nil, fmt.Errorf("no other device matches %q", prefix)
	}
	removed := *target
	epoch := c.st.Epoch + 1
	key := make([]byte, 32)
	rand.Read(key)
	if err := app.SecretSet(c.prefix()+"key-"+strconv.Itoa(epoch), key); err != nil {
		return nil, err
	}
	for _, d := range keep {
		if err := c.putEnvelope(d, epoch, key); err != nil {
			return nil, err
		}
	}
	// every host is uploaded again under the new key, forgetting the local
	// hashes makes the push treat all of them as changed
	for id, e := range c.st.Entries {
		e.Local = ""
		c.st.Entries[id] = e
	}
	c.st.Epoch = epoch
	if _, err := c.pushOnce(keep); err != nil {
		return nil, err
	}
	code, b, _, err := c.call("DELETE", "/devices/"+removed.ID, nil, nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusNoContent {
		return nil, serverError(code, b)
	}
	return &removed, nil
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
}

func (c *Client) Status() (*Status, error) {
	if err := c.load(); err != nil {
		return nil, err
	}
	st := &Status{
		Server: c.st.Server, Account: c.st.Account, Device: c.st.DeviceID, Name: c.st.Name,
		Fingerprint: Fingerprint(c.self().SignPub), Counter: c.st.Counter,
		Devices: c.st.Trusted, Waiting: c.st.Approver != "", LastSync: c.st.LastSync,
	}
	if len(c.st.Head) >= 8 {
		st.State = c.st.Head[:8]
	}
	return st, nil
}

// Leave forgets sync on this machine, the hosts stay, the account and the
// other devices are not touched
func (c *Client) Leave() error {
	b, err := os.ReadFile(c.statePath())
	if err == nil {
		var st state
		if json.Unmarshal(b, &st) == nil {
			for e := 1; e <= st.Epoch; e++ {
				app.SecretDelete(c.prefix() + "key-" + strconv.Itoa(e))
			}
		}
	}
	app.SecretDelete(c.prefix() + "device")
	if err := os.Remove(c.statePath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	c.st = nil
	return nil
}
