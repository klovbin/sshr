// Package api is the local REST API of sshr for other programs, editor
// plugins, panels, scripts, it listens on a unix socket or on a loopback
// address with a token, never on the network, and never returns passwords,
// keys or references to them
package api

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"sshr.dev/internal/app"
)

// Options are the choices made when the server starts
type Options struct {
	// Token is required as "Authorization: Bearer <token>" when set, a TCP
	// listener always has one, any local program can reach a loopback port
	Token string
	// AllowCommands enables POST /v1/hosts/{host}/run, off by default
	AllowCommands bool
}

// uploadMax bounds an upload body
const uploadMax = 100 << 20

// Server is the API, an http.Handler, Close stops the tunnels it opened
type Server struct {
	http.Handler
	a *api
}

// New makes the API for store
func New(store *app.Store, opts Options) *Server {
	a := &api{store: store, opts: opts, tunnels: map[string]*tunnel{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/hosts", a.listHosts)
	mux.HandleFunc("POST /v1/hosts", a.addHost)
	mux.HandleFunc("GET /v1/hosts/{host}", a.getHost)
	mux.HandleFunc("DELETE /v1/hosts/{host}", a.deleteHost)
	mux.HandleFunc("GET /v1/hosts/{host}/connect", a.connect)
	mux.HandleFunc("POST /v1/hosts/{host}/upload", a.upload)
	mux.HandleFunc("POST /v1/hosts/{host}/run", a.run)
	mux.HandleFunc("POST /v1/hosts/{host}/tunnels", a.openTunnel)
	mux.HandleFunc("GET /v1/tunnels", a.listTunnels)
	mux.HandleFunc("DELETE /v1/tunnels/{id}", a.closeTunnel)
	return &Server{Handler: a.guard(mux), a: a}
}

// Close stops every tunnel the API opened
func (s *Server) Close() {
	s.a.mu.Lock()
	defer s.a.mu.Unlock()
	for _, t := range s.a.tunnels {
		t.cmd.Process.Kill()
	}
}

type api struct {
	store *app.Store
	opts  Options
	mu    sync.Mutex
	// tunnels are ssh -N processes started through the API, they live as
	// long as the server
	tunnels map[string]*tunnel
}

// guard checks the token and refuses requests a browser page could send:
// a Host other than a loopback name (DNS rebinding) or any Origin header
func (a *api) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" {
			fail(w, http.StatusForbidden, errors.New("requests from web pages are not accepted"))
			return
		}
		if a.opts.Token != "" {
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if host != "localhost" && net.ParseIP(host) == nil {
				fail(w, http.StatusForbidden, errors.New("connect to 127.0.0.1 or localhost"))
				return
			}
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(a.opts.Token)) != 1 {
				fail(w, http.StatusUnauthorized, errors.New("missing or wrong token"))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	reply(w, code, map[string]string{"error": err.Error()})
}

// findHost resolves {host}, a missing or ambiguous name is answered here
func (a *api) findHost(w http.ResponseWriter, r *http.Request) *app.Host {
	h, err := a.store.Find(r.PathValue("host"))
	var amb *app.AmbiguousError
	switch {
	case errors.As(err, &amb):
		fail(w, http.StatusConflict, fmt.Errorf("%q matches %d hosts, use the ID", amb.Query, len(amb.Hosts)))
		return nil
	case errors.Is(err, app.ErrNotFound):
		fail(w, http.StatusNotFound, fmt.Errorf("no saved host %q", r.PathValue("host")))
		return nil
	case err != nil:
		fail(w, http.StatusInternalServerError, err)
		return nil
	}
	return h
}

func (a *api) listHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := a.store.List()
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]app.HostSummary, 0, len(hosts))
	for i := range hosts {
		out = append(out, hosts[i].Summary())
	}
	reply(w, http.StatusOK, out)
}

func (a *api) getHost(w http.ResponseWriter, r *http.Request) {
	if h := a.findHost(w, r); h != nil {
		reply(w, http.StatusOK, h.Summary())
	}
}

// newHost is what POST /v1/hosts takes, secrets that would have to travel
// through the API (a password to save, a pasted key) are not accepted, nor
// are 1Password and Bitwarden references, any local client could link a
// server of its choice to any item and the next connect would send the
// secret there, those are added in the app or the CLI
type newHost struct {
	Name        string   `json:"name"`
	Host        string   `json:"host"`
	User        string   `json:"user"`
	Port        int      `json:"port"`
	Key         string   `json:"key"`
	Agent       *string  `json:"agent"`
	AgentKey    string   `json:"agent_key"`
	AskPassword bool     `json:"ask_password"`
	OPPassword  string   `json:"op_password"`
	OPKey       string   `json:"op_key"`
	BWPassword  string   `json:"bw_password"`
	BWKey       string   `json:"bw_key"`
	Jump        string   `json:"jump"`
	Session     string   `json:"session"`
	Forwards    []string `json:"forwards"`
	Tags        []string `json:"tags"`
	Password    string   `json:"password"`
	PrivateKey  string   `json:"private_key"`
}

func (a *api) addHost(w http.ResponseWriter, r *http.Request) {
	var in newHost
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if in.Password != "" || in.PrivateKey != "" {
		fail(w, http.StatusBadRequest, errors.New("passwords and private keys are not taken through the API, add them in the app or with sshr add"))
		return
	}
	if in.OPPassword != "" || in.OPKey != "" || in.BWPassword != "" || in.BWKey != "" {
		fail(w, http.StatusBadRequest, errors.New("1Password and Bitwarden references are not taken through the API, link them in the app or with sshr add"))
		return
	}
	h := app.Host{Name: in.Name, Host: in.Host, User: in.User, Port: in.Port, Key: in.Key, Jump: in.Jump, Session: in.Session, Tags: in.Tags}
	switch {
	case in.Key != "":
		h.Key = app.ExpandHome(in.Key)
		if err := app.CheckPrivateKey(h.Key); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
	case in.Agent != nil:
		h.KeyMode, h.Agent, h.AgentKey = app.KeyAgent, *in.Agent, in.AgentKey
	case in.AskPassword:
		h.PasswordMode = app.PasswordAsk
	}
	if len(in.Forwards) > 0 {
		fs, err := app.ParseForwards(strings.Join(in.Forwards, "\n"))
		if err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		h.Forwards = fs
	}
	saved, err := a.store.Add(h)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	reply(w, http.StatusCreated, saved.Summary())
}

func (a *api) deleteHost(w http.ResponseWriter, r *http.Request) {
	h := a.findHost(w, r)
	if h == nil {
		return
	}
	if err := a.store.Delete(h.ID); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// connect gives the command line that opens a session, the caller runs it
// in a terminal of its own, the server has none
func (a *api) connect(w http.ResponseWriter, r *http.Request) {
	h := a.findHost(w, r)
	if h == nil {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	reply(w, http.StatusOK, map[string]any{"argv": []string{exe, "connect", h.ID}})
}

func (a *api) upload(w http.ResponseWriter, r *http.Request) {
	h := a.findHost(w, r)
	if h == nil {
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, uploadMax+1))
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if len(data) > uploadMax {
		fail(w, http.StatusRequestEntityTooLarge, fmt.Errorf("at most %d MiB", uploadMax>>20))
		return
	}
	ext := r.URL.Query().Get("ext")
	if ext == "" {
		ext = "bin"
	}
	for _, c := range ext {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') || len(ext) > 10 {
			fail(w, http.StatusBadRequest, errors.New("ext must be up to 10 letters or digits"))
			return
		}
	}
	remote, err := a.store.UploadImage(h, data, ext, true)
	if err != nil {
		fail(w, http.StatusBadGateway, err)
		return
	}
	reply(w, http.StatusOK, map[string]string{"host": h.Name, "path": remote})
}

func (a *api) run(w http.ResponseWriter, r *http.Request) {
	if !a.opts.AllowCommands {
		fail(w, http.StatusForbidden, errors.New("commands are off, start sshr serve with --allow-commands or set api_commands"))
		return
	}
	h := a.findHost(w, r)
	if h == nil {
		return
	}
	var in struct {
		Command        string `json:"command"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil || strings.TrimSpace(in.Command) == "" {
		fail(w, http.StatusBadRequest, errors.New(`expected {"command": "..."}`))
		return
	}
	if in.TimeoutSeconds <= 0 {
		in.TimeoutSeconds = 60
	}
	if in.TimeoutSeconds > 600 {
		in.TimeoutSeconds = 600
	}
	fmt.Fprintf(os.Stderr, "sshr serve: run on %s: %s\n", h.Name, in.Command)
	res, err := a.store.RunRemote(h, in.Command, nil, time.Duration(in.TimeoutSeconds)*time.Second)
	if err != nil {
		fail(w, http.StatusBadGateway, err)
		return
	}
	reply(w, http.StatusOK, map[string]any{
		"host": h.Name, "exit_code": res.ExitCode,
		"stdout": string(res.Stdout), "stderr": string(res.Stderr), "truncated": res.Truncated,
	})
}

type tunnel struct {
	ID       string   `json:"id"`
	Host     string   `json:"host"`
	Forwards []string `json:"forwards"`
	Started  string   `json:"started"`
	cmd      *exec.Cmd
	stop     func()
}

// tunnelStartup is how long a new tunnel has to fail, a taken port or a
// refused login, before it counts as open
const tunnelStartup = 2 * time.Second

func (a *api) openTunnel(w http.ResponseWriter, r *http.Request) {
	h := a.findHost(w, r)
	if h == nil {
		return
	}
	var in struct {
		Forwards []string `json:"forwards"`
	}
	json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in)
	if len(in.Forwards) == 0 {
		in.Forwards = []string{"all"}
	}
	fs, err := app.FindForwards(h.Forwards, in.Forwards)
	if err != nil || len(fs) == 0 {
		if err == nil {
			err = fmt.Errorf("%s has no saved forwards", h.Name)
		}
		fail(w, http.StatusBadRequest, err)
		return
	}
	if h.PasswordMode == app.PasswordAsk {
		fail(w, http.StatusBadRequest, app.ErrAsksPassword)
		return
	}
	args, err := a.store.ConnectArgs(h)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if !h.PasswordFromSshr() {
		args = append(args, "-o", "BatchMode=yes")
	}
	args = append(args, "-N", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=30")
	t := &tunnel{Host: h.Name, Started: time.Now().UTC().Format(time.RFC3339)}
	for _, f := range fs {
		args = append(args, f.Args()...)
		t.Forwards = append(t.Forwards, f.String())
	}
	cmd := exec.Command("ssh", append(args, "--", h.Dest())...)
	cmd.Env = append(os.Environ(), "SSHR_BATCH=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stop, err := app.AttachAuth(cmd, h)
	if err != nil {
		fail(w, http.StatusBadGateway, err)
		return
	}
	if err := cmd.Start(); err != nil {
		stop()
		fail(w, http.StatusInternalServerError, err)
		return
	}
	t.ID = fmt.Sprintf("%d", cmd.Process.Pid)
	t.cmd, t.stop = cmd, stop
	done := make(chan struct{})
	go func() {
		cmd.Wait()
		stop()
		a.mu.Lock()
		delete(a.tunnels, t.ID)
		a.mu.Unlock()
		close(done)
	}()
	select {
	case <-done:
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = "ssh exited"
		}
		fail(w, http.StatusBadGateway, fmt.Errorf("tunnel to %s did not open: %s", h.Name, msg))
		return
	case <-time.After(tunnelStartup):
	}
	a.mu.Lock()
	select {
	case <-done:
		// it died between the check above and now, nothing to keep
	default:
		a.tunnels[t.ID] = t
	}
	a.mu.Unlock()
	reply(w, http.StatusCreated, t)
}

func (a *api) listTunnels(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	out := make([]*tunnel, 0, len(a.tunnels))
	for _, t := range a.tunnels {
		out = append(out, t)
	}
	a.mu.Unlock()
	reply(w, http.StatusOK, out)
}

func (a *api) closeTunnel(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	t := a.tunnels[r.PathValue("id")]
	a.mu.Unlock()
	if t == nil {
		fail(w, http.StatusNotFound, errors.New("no such tunnel"))
		return
	}
	t.cmd.Process.Kill()
	w.WriteHeader(http.StatusNoContent)
}
