// Package syncserver stores sync data for sshr accounts, it sees only
// device public keys, encrypted blobs and manifests it cannot verify, every
// device authenticates with its own bearer token
package syncserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"sshr.dev/internal/fileio"
	"sshr.dev/internal/syncproto"
)

var (
	idPattern   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Limits per account
const (
	maxPending   = 10
	keepHistory  = 1000
	orphanMaxAge = 24 * time.Hour
)

// Server is the HTTP handler of the sync server
type Server struct {
	// TrustProxy takes the client address from the last X-Forwarded-For
	// entry when the request comes from this machine, set it behind a TLS
	// reverse proxy, where every request comes from 127.0.0.1
	TrustProxy bool

	dir   string
	mux   *http.ServeMux
	mu    sync.Mutex
	locks map[string]*sync.Mutex
	// creates limits account creation and joins per client address
	creates map[string][]time.Time
	swept   time.Time
	// Now is the clock of the recovery wait, nil is time.Now, tests move it
	Now func() time.Time
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// New serves accounts stored under dir
func New(dir string) (*Server, error) {
	if err := os.MkdirAll(filepath.Join(dir, "accounts"), 0o700); err != nil {
		return nil, err
	}
	s := &Server{dir: dir, mux: http.NewServeMux(), locks: map[string]*sync.Mutex{}, creates: map[string][]time.Time{}}
	s.mux.HandleFunc("GET /v1/health", s.health)
	s.mux.HandleFunc("POST /v1/accounts", s.newAccount)
	s.mux.HandleFunc("POST /v1/accounts/{a}/join", s.join)
	s.mux.HandleFunc("GET /v1/accounts/{a}/devices", s.auth(s.listDevices))
	s.mux.HandleFunc("POST /v1/accounts/{a}/devices/{d}/activate", s.auth(s.activate))
	s.mux.HandleFunc("DELETE /v1/accounts/{a}/devices/{d}", s.auth(s.removeDevice))
	s.mux.HandleFunc("PUT /v1/accounts/{a}/blobs/{h}", s.auth(s.putBlob))
	s.mux.HandleFunc("GET /v1/accounts/{a}/blobs/{h}", s.auth(s.getBlob))
	s.mux.HandleFunc("PUT /v1/accounts/{a}/envelopes/{d}", s.auth(s.putEnvelope))
	s.mux.HandleFunc("GET /v1/accounts/{a}/envelopes/{d}", s.auth(s.getEnvelope))
	s.mux.HandleFunc("GET /v1/accounts/{a}/manifest", s.auth(s.getManifest))
	s.mux.HandleFunc("GET /v1/accounts/{a}/manifests", s.auth(s.listManifests))
	s.mux.HandleFunc("PUT /v1/accounts/{a}/manifest", s.auth(s.putManifest))
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// health answers a monitor: 200 while the data folder can be written,
// 503 when it cannot, nothing about accounts
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	f, err := os.CreateTemp(s.dir, ".health-*")
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "the data folder cannot be written")
		return
	}
	f.Close()
	os.Remove(f.Name())
	reply(w, http.StatusOK, map[string]bool{"ok": true})
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	reply(w, code, map[string]string{"error": msg})
}

func (s *Server) accountDir(a string) string { return filepath.Join(s.dir, "accounts", a) }

// lock serializes writes to one account
func (s *Server) lock(a string) func() {
	s.mu.Lock()
	l := s.locks[a]
	if l == nil {
		l = &sync.Mutex{}
		s.locks[a] = l
	}
	s.mu.Unlock()
	l.Lock()
	return l.Unlock
}

// allowCreate rate-limits new accounts and joins, 10 an hour per address
// clientAddr is the address the join limit counts, the proxy's view of
// the client when TrustProxy is on and the request came over loopback
func (s *Server) clientAddr(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	if p := net.ParseIP(ip); s.TrustProxy && p != nil && p.IsLoopback() {
		hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		if last := strings.TrimSpace(hops[len(hops)-1]); net.ParseIP(last) != nil {
			return last
		}
	}
	return ip
}

func (s *Server) allowCreate(r *http.Request) bool {
	ip := s.clientAddr(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	// addresses seen once would stay for ever, a sweep now and then drops
	// the ones whose last try is over an hour old
	if now.Sub(s.swept) > 10*time.Minute {
		for addr, times := range s.creates {
			if len(times) == 0 || now.Sub(times[len(times)-1]) >= time.Hour {
				delete(s.creates, addr)
			}
		}
		s.swept = now
	}
	var kept []time.Time
	for _, t := range s.creates[ip] {
		if now.Sub(t) < time.Hour {
			kept = append(kept, t)
		}
	}
	if len(kept) >= 10 {
		s.creates[ip] = kept
		return false
	}
	s.creates[ip] = append(kept, now)
	return true
}

type deviceFile struct {
	syncproto.DeviceRecord
	TokenHash string    `json:"token_hash"`
	Created   time.Time `json:"created"`
}

func (s *Server) loadDevices(a string) ([]deviceFile, error) {
	b, err := os.ReadFile(filepath.Join(s.accountDir(a), "devices.json"))
	if err != nil {
		return nil, err
	}
	var ds []deviceFile
	return ds, json.Unmarshal(b, &ds)
}

func (s *Server) saveDevices(a string, ds []deviceFile) error {
	b, err := json.MarshalIndent(ds, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(s.accountDir(a), "devices.json"), b)
}

// writeFile replaces path through a temp file of its own and a rename, two
// requests writing the same file never share a temp file
func writeFile(path string, data []byte) error {
	return fileio.WriteFile(path, data, 0o600)
}

func newToken() (token, hash string, err error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(b[:])
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:]), nil
}

// checkDevice refuses a device whose ID is not derived from its key
func checkDevice(d syncproto.Device) error {
	if len(d.SignPub) != 32 || len(d.KEMPub) == 0 || len(d.KEMPub) > 4096 || len(d.Name) > 64 {
		return errors.New("bad device keys")
	}
	if d.ID != syncproto.DeviceID(d.SignPub) {
		return errors.New("device id does not match its key")
	}
	for _, r := range d.Name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return errors.New("control characters in the device name")
		}
	}
	return nil
}

func (s *Server) newAccount(w http.ResponseWriter, r *http.Request) {
	if !s.allowCreate(r) {
		fail(w, http.StatusTooManyRequests, "too many new accounts from this address")
		return
	}
	var req syncproto.NewAccountRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil || checkDevice(req.Device) != nil {
		fail(w, http.StatusBadRequest, "bad device")
		return
	}
	var b [16]byte
	rand.Read(b[:])
	a := hex.EncodeToString(b[:])
	token, hash, err := newToken()
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	dir := s.accountDir(a)
	for _, sub := range []string{"blobs", "envelopes", "manifests"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	ds := []deviceFile{{DeviceRecord: syncproto.DeviceRecord{Device: req.Device, Active: true}, TokenHash: hash, Created: time.Now().UTC()}}
	if err := s.saveDevices(a, ds); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	reply(w, http.StatusCreated, syncproto.TokenResponse{Account: a, Token: token})
}

// join registers a device that waits for an existing device to approve it
func (s *Server) join(w http.ResponseWriter, r *http.Request) {
	a := r.PathValue("a")
	if !idPattern.MatchString(a) {
		fail(w, http.StatusNotFound, "no such account")
		return
	}
	if !s.allowCreate(r) {
		fail(w, http.StatusTooManyRequests, "too many requests from this address")
		return
	}
	var req syncproto.NewAccountRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil || checkDevice(req.Device) != nil {
		fail(w, http.StatusBadRequest, "bad device")
		return
	}
	defer s.lock(a)()
	ds, err := s.loadDevices(a)
	if err != nil {
		fail(w, http.StatusNotFound, "no such account")
		return
	}
	pending := 0
	for _, d := range ds {
		if d.ID == req.Device.ID {
			fail(w, http.StatusConflict, "device already joined")
			return
		}
		if !d.Active {
			pending++
		}
	}
	if pending >= maxPending {
		fail(w, http.StatusTooManyRequests, "too many devices waiting for approval")
		return
	}
	token, hash, err := newToken()
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	ds = append(ds, deviceFile{DeviceRecord: syncproto.DeviceRecord{Device: req.Device}, TokenHash: hash, Created: time.Now().UTC()})
	if err := s.saveDevices(a, ds); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	reply(w, http.StatusCreated, syncproto.TokenResponse{Account: a, Token: token})
}

type ctxDevice struct {
	id     string
	active bool
}

// auth checks the bearer token of a device of account {a}, only an active
// device gets through, a waiting one gets 403 everywhere, its envelope is
// written only after it is approved
func (s *Server) auth(next func(http.ResponseWriter, *http.Request, ctxDevice)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a := r.PathValue("a")
		if !idPattern.MatchString(a) {
			fail(w, http.StatusNotFound, "no such account")
			return
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		sum := sha256.Sum256([]byte(token))
		hash := hex.EncodeToString(sum[:])
		ds, err := s.loadDevices(a)
		if err != nil {
			fail(w, http.StatusUnauthorized, "unknown account or token")
			return
		}
		for _, d := range ds {
			if subtle.ConstantTimeCompare([]byte(d.TokenHash), []byte(hash)) == 1 {
				if !d.Active {
					fail(w, http.StatusForbidden, "this device is waiting for approval from another device")
					return
				}
				next(w, r, ctxDevice{id: d.ID, active: true})
				return
			}
		}
		fail(w, http.StatusUnauthorized, "unknown account or token")
	}
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request, _ ctxDevice) {
	ds, err := s.loadDevices(r.PathValue("a"))
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]syncproto.DeviceRecord, len(ds))
	for i, d := range ds {
		out[i] = d.DeviceRecord
	}
	reply(w, http.StatusOK, out)
}

func (s *Server) activate(w http.ResponseWriter, r *http.Request, dev ctxDevice) {
	a, id := r.PathValue("a"), r.PathValue("d")
	defer s.lock(a)()
	// a machine restored from the recovery kit is the primary of the head
	// and is activated by the kit device that handed the account to it
	if m, _, err := s.head(a); err != nil || m == nil || m.Recovery == "" || dev.id != m.Recovery || id != m.Primary {
		if !s.onlyPrimary(w, a, dev, "approves devices") {
			return
		}
	}
	ds, err := s.loadDevices(a)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	for i := range ds {
		if ds[i].ID == id {
			ds[i].Active = true
			if err := s.saveDevices(a, ds); err != nil {
				fail(w, http.StatusInternalServerError, err.Error())
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	fail(w, http.StatusNotFound, "no such device")
}

func (s *Server) removeDevice(w http.ResponseWriter, r *http.Request, dev ctxDevice) {
	a, id := r.PathValue("a"), r.PathValue("d")
	defer s.lock(a)()
	if !s.onlyPrimary(w, a, dev, "removes devices") {
		return
	}
	ds, err := s.loadDevices(a)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	kept := ds[:0]
	for _, d := range ds {
		if d.ID != id {
			kept = append(kept, d)
		}
	}
	if len(kept) == len(ds) {
		fail(w, http.StatusNotFound, "no such device")
		return
	}
	if err := s.saveDevices(a, kept); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	os.Remove(filepath.Join(s.accountDir(a), "envelopes", id+".json"))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) putBlob(w http.ResponseWriter, r *http.Request, _ ctxDevice) {
	a, h := r.PathValue("a"), r.PathValue("h")
	if !hashPattern.MatchString(h) {
		fail(w, http.StatusBadRequest, "bad hash")
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, syncproto.MaxBlob+1))
	if err != nil || len(data) > syncproto.MaxBlob {
		fail(w, http.StatusRequestEntityTooLarge, "blob too large")
		return
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != h {
		fail(w, http.StatusBadRequest, "hash does not match the body")
		return
	}
	path := filepath.Join(s.accountDir(a), "blobs", h)
	// one account does not fill the disk of the server, a blob already
	// stored costs nothing again
	if _, err := os.Stat(path); err != nil {
		if n, size := blobUsage(filepath.Dir(path)); n+1 > syncproto.MaxAccountBlobs || size+int64(len(data)) > syncproto.MaxAccountBytes {
			fail(w, http.StatusInsufficientStorage, fmt.Sprintf("the account is full (%d blobs, %d MiB), the server keeps at most %d blobs and %d MiB per account", n, size>>20, syncproto.MaxAccountBlobs, syncproto.MaxAccountBytes>>20))
			return
		}
	}
	// blobs are content-addressed, writing one twice is harmless
	if err := writeFile(path, data); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// blobUsage counts the blobs in dir and their bytes
func blobUsage(dir string) (int, int64) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0
	}
	var n int
	var size int64
	for _, e := range entries {
		if fi, err := e.Info(); err == nil && fi.Mode().IsRegular() && hashPattern.MatchString(e.Name()) {
			n++
			size += fi.Size()
		}
	}
	return n, size
}

func (s *Server) getBlob(w http.ResponseWriter, r *http.Request, _ ctxDevice) {
	h := r.PathValue("h")
	if !hashPattern.MatchString(h) {
		fail(w, http.StatusBadRequest, "bad hash")
		return
	}
	data, err := os.ReadFile(filepath.Join(s.accountDir(r.PathValue("a")), "blobs", h))
	if err != nil {
		fail(w, http.StatusNotFound, "no such blob")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

func (s *Server) putEnvelope(w http.ResponseWriter, r *http.Request, _ ctxDevice) {
	a, id := r.PathValue("a"), r.PathValue("d")
	if !idPattern.MatchString(id) {
		fail(w, http.StatusBadRequest, "bad device id")
		return
	}
	var env syncproto.Envelope
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&env); err != nil {
		fail(w, http.StatusBadRequest, "bad envelope")
		return
	}
	// a key of an older epoch never replaces a newer one, a device still
	// delivering an old key change would lock the device out of the vault
	defer s.lock(a)()
	path := filepath.Join(s.accountDir(a), "envelopes", id+".json")
	var cur syncproto.Envelope
	if old, err := os.ReadFile(path); err == nil && json.Unmarshal(old, &cur) == nil && cur.Epoch > env.Epoch {
		fail(w, http.StatusConflict, "a newer key is stored for this device")
		return
	}
	b, _ := json.Marshal(env)
	if err := writeFile(path, b); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// getEnvelope gives a device only its own envelope
func (s *Server) getEnvelope(w http.ResponseWriter, r *http.Request, dev ctxDevice) {
	id := r.PathValue("d")
	if id != dev.id {
		fail(w, http.StatusForbidden, "a device reads only its own envelope")
		return
	}
	b, err := os.ReadFile(filepath.Join(s.accountDir(r.PathValue("a")), "envelopes", id+".json"))
	if err != nil {
		fail(w, http.StatusNotFound, "no envelope for this device yet")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

// manifests are stored as manifests/<counter>.json, the highest is current
func (s *Server) counters(a string) []uint64 {
	entries, _ := os.ReadDir(filepath.Join(s.accountDir(a), "manifests"))
	var out []uint64
	for _, e := range entries {
		if n, err := strconv.ParseUint(strings.TrimSuffix(e.Name(), ".json"), 10, 64); err == nil && strings.HasSuffix(e.Name(), ".json") {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (s *Server) current(a string) uint64 {
	cs := s.counters(a)
	if len(cs) == 0 {
		return 0
	}
	return cs[len(cs)-1]
}

// head is the stored head manifest of account a and who signed it, nil
// before the first push
func (s *Server) head(a string) (*syncproto.Manifest, *syncproto.Signed, error) {
	c := s.current(a)
	if c == 0 {
		return nil, nil, nil
	}
	b, err := os.ReadFile(filepath.Join(s.accountDir(a), "manifests", fmt.Sprintf("%d.json", c)))
	if err != nil {
		return nil, nil, err
	}
	var sm syncproto.Signed
	var m syncproto.Manifest
	if err := json.Unmarshal(b, &sm); err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(sm.Body, &m); err != nil {
		return nil, nil, err
	}
	return &m, &sm, nil
}

// onlyPrimary refuses a device that is not the primary device of the head
// of account a, an account no primary was named in yet lets every device
// as before
func (s *Server) onlyPrimary(w http.ResponseWriter, a string, dev ctxDevice, what string) bool {
	m, _, err := s.head(a)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return false
	}
	if m != nil && m.Version >= 2 && m.Primary != "" && m.Primary != dev.id {
		fail(w, http.StatusForbidden, "only the primary device of the account "+what)
		return false
	}
	return true
}

func (s *Server) getManifest(w http.ResponseWriter, r *http.Request, _ ctxDevice) {
	a := r.PathValue("a")
	c := s.current(a)
	if c == 0 {
		fail(w, http.StatusNotFound, "no manifest yet")
		return
	}
	b, err := os.ReadFile(filepath.Join(s.accountDir(a), "manifests", fmt.Sprintf("%d.json", c)))
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("ETag", strconv.FormatUint(c, 10))
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

// listManifests returns the manifests after ?after=N, a client checks the
// chain from its last one to the current one
func (s *Server) listManifests(w http.ResponseWriter, r *http.Request, _ ctxDevice) {
	a := r.PathValue("a")
	after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	var out []json.RawMessage
	for _, c := range s.counters(a) {
		if c <= after {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.accountDir(a), "manifests", fmt.Sprintf("%d.json", c)))
		if err != nil {
			continue
		}
		out = append(out, b)
		if len(out) >= 500 {
			break
		}
	}
	reply(w, http.StatusOK, out)
}

// putManifest replaces the manifest if If-Match names the current counter,
// two devices pushing at once cannot overwrite each other, the new counter
// must be the next one and every blob it names must be stored already
func (s *Server) putManifest(w http.ResponseWriter, r *http.Request, _ ctxDevice) {
	a := r.PathValue("a")
	expect, err := strconv.ParseUint(r.Header.Get("If-Match"), 10, 64)
	if err != nil {
		fail(w, http.StatusPreconditionRequired, "If-Match with the current counter is required")
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, syncproto.MaxManifest+1))
	if err != nil || len(data) > syncproto.MaxManifest {
		fail(w, http.StatusRequestEntityTooLarge, "manifest too large")
		return
	}
	var sm syncproto.Signed
	var m syncproto.Manifest
	if json.Unmarshal(data, &sm) != nil || json.Unmarshal(sm.Body, &m) != nil || m.Account != a {
		fail(w, http.StatusBadRequest, "bad manifest")
		return
	}
	defer s.lock(a)()
	cur := s.current(a)
	if cur != expect {
		w.Header().Set("ETag", strconv.FormatUint(cur, 10))
		fail(w, http.StatusPreconditionFailed, "the manifest changed, pull and try again")
		return
	}
	if m.Counter != cur+1 {
		fail(w, http.StatusBadRequest, "counter must be the current one plus one")
		return
	}
	if err := s.checkRoles(a, &sm, &m); err != nil {
		fail(w, http.StatusForbidden, err.Error())
		return
	}
	dir := s.accountDir(a)
	live := map[string]bool{}
	for _, e := range m.Entries {
		if e.Deleted {
			continue
		}
		if !hashPattern.MatchString(e.Hash) {
			fail(w, http.StatusBadRequest, "bad entry hash")
			return
		}
		if _, err := os.Stat(filepath.Join(dir, "blobs", e.Hash)); err != nil {
			fail(w, http.StatusConflict, "a blob of the manifest is missing, upload blobs first")
			return
		}
		live[e.Hash] = true
	}
	if err := writeFile(filepath.Join(dir, "manifests", fmt.Sprintf("%d.json", m.Counter)), data); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if m.Claim != 0 && m.Claim == m.Counter {
		// when the recovery kit claimed the account, the hand-over waits
		// from here
		os.MkdirAll(filepath.Join(dir, "claims"), 0o700)
		writeFile(filepath.Join(dir, "claims", strconv.FormatUint(m.Counter, 10)), []byte(strconv.FormatInt(s.now().Unix(), 10)))
	}
	s.collect(a, live)
	w.Header().Set("ETag", strconv.FormatUint(m.Counter, 10))
	w.WriteHeader(http.StatusNoContent)
}

// checkRoles applies the rule of the primary device to a new manifest
// against the stored head (syncproto.CheckPrimary), a manifest that needs
// the primary must carry a valid signature of the device it names as
// signer, the server cannot check the MAC but it holds the signing keys of
// the devices in the head, the clients check the same again
func (s *Server) checkRoles(a string, sm *syncproto.Signed, m *syncproto.Manifest) error {
	prev, prevSigned, err := s.head(a)
	if err != nil {
		return err
	}
	// a manifest every client refuses would still become the head and stop
	// the account, what the server can check without the vault key it does
	if m.Version > syncproto.FormatVersion {
		return fmt.Errorf("manifest of format %d, this server knows up to %d", m.Version, syncproto.FormatVersion)
	}
	for _, d := range m.Devices {
		if syncproto.DeviceID(d.SignPub) != d.ID {
			return errors.New("the manifest lists a device whose id does not match its key")
		}
	}
	if id := syncproto.RepeatedDevice(m.Devices); id != "" {
		return errors.New("the manifest lists a device twice")
	}
	if prev == nil {
		return nil
	}
	if m.Prev != syncproto.BodyHash(prevSigned.Body) {
		return errors.New("the manifest does not follow the current one")
	}
	if m.Epoch < prev.Epoch {
		return errors.New("the manifest goes back to an older vault key")
	}
	step, err := syncproto.CheckPrimary(prev, m, sm.Signer)
	if err != nil {
		return err
	}
	if m.Version < 2 {
		return nil
	}
	if step == syncproto.StepRecover {
		// the wait since the claim by the clock of the server, a stolen kit
		// cannot hand the account over before the owner had time to cancel
		b, err := os.ReadFile(filepath.Join(s.accountDir(a), "claims", strconv.FormatUint(prev.Claim, 10)))
		at, perr := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		if err != nil || perr != nil {
			return errors.New("the claim of the recovery kit is not known to this server")
		}
		if left := time.Unix(at, 0).Add(time.Duration(prev.RecoveryWait) * time.Second).Sub(s.now()); left > 0 {
			return fmt.Errorf("the recovery kit hands the account over only after the wait, %s left", left.Round(time.Minute))
		}
	}
	for _, d := range prev.Devices {
		if d.ID == sm.Signer {
			if len(d.SignPub) != ed25519.PublicKeySize || !ed25519.Verify(d.SignPub, syncproto.SignInput(sm.Body), sm.Sig) {
				return errors.New("the signature of the manifest does not verify")
			}
			return nil
		}
	}
	return errors.New("the manifest is signed by a device that is not in the account")
}

// collect drops old manifests past keepHistory and blobs no manifest
// needs, a blob is kept a day so a push in progress does not lose it
func (s *Server) collect(a string, live map[string]bool) {
	dir := s.accountDir(a)
	cs := s.counters(a)
	for len(cs) > keepHistory {
		os.Remove(filepath.Join(dir, "manifests", fmt.Sprintf("%d.json", cs[0])))
		cs = cs[1:]
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "blobs"))
	for _, e := range entries {
		if live[e.Name()] {
			continue
		}
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > orphanMaxAge {
			os.Remove(filepath.Join(dir, "blobs", e.Name()))
		}
	}
}
