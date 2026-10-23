// Package mcp serves sshr to AI assistants over the Model Context Protocol,
// JSON-RPC on stdin and stdout, the assistant starts `sshr mcp` itself, so
// the server is local to the user and needs no token
package mcp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"sshr.dev/internal/app"
	"sshr.dev/internal/audit"
)

// protocol versions this server speaks, newest first
var versions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

// logOut is where the server says what it runs, stderr, which the MCP
// client shows or logs
var logOut io.Writer = os.Stderr

// Options are the choices made when the server starts
type Options struct {
	// AllowCommands offers run_command, off by default: an assistant that
	// can run commands on every saved server can also break them
	AllowCommands bool
	Version       string
	// Audit records uploads and commands, nil keeps no record
	Audit *audit.Log
	// CommandsAllowed says whether run_command may run on a host, nil
	// allows every host
	CommandsAllowed func(*app.Host) error
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	// Result and Error mark a response of the client to a request of the
	// server, it is not a request and gets no answer
	Result json.RawMessage `json:"result,omitempty"`
	Error  json.RawMessage `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Serve answers requests from r on w until r ends
func Serve(r io.Reader, w io.Writer, store *app.Store, opts Options) error {
	s := &server{store: store, opts: opts, w: w, slots: make(chan struct{}, maxRunning)}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	var wg sync.WaitGroup
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			s.send(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
			continue
		}
		if len(req.ID) == 0 {
			// a notification, initialized and cancelled need no answer
			continue
		}
		if req.Method == "" && (len(req.Result) > 0 || len(req.Error) > 0) {
			// a response is never answered, an answer to it would loop
			continue
		}
		// a command can take minutes, other requests are answered meanwhile
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(req)
		}()
	}
	wg.Wait()
	return sc.Err()
}

// maxRunning is how many uploads and commands run at once, as in sshr run,
// the others wait for a free slot
const maxRunning = 8

type server struct {
	store *app.Store
	opts  Options
	mu    sync.Mutex
	w     io.Writer
	slots chan struct{}
	// client is what the client said it is in initialize
	client string
}

// begin writes the start of an action to the audit log, an action whose
// start cannot be written does not run
func (s *server) begin(action string, h *app.Host, command string) (func(int, int64, error), error) {
	s.mu.Lock()
	client := s.client
	s.mu.Unlock()
	return s.opts.Audit.Begin(audit.Record{Surface: "mcp", Client: client, Action: action,
		HostID: h.ID, HostName: h.Name, Target: fmt.Sprintf("%s:%d", h.Dest(), h.Port), Command: command})
}

func exitOf(err error) int {
	if err != nil {
		return -1
	}
	return 0
}

func (s *server) send(resp response) {
	b, err := json.Marshal(resp)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.w.Write(append(b, '\n'))
}

func (s *server) handle(req request) {
	resp := response{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
			ClientInfo      struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"clientInfo"`
		}
		json.Unmarshal(req.Params, &p)
		// the client names itself, the parent process is what started sshr
		s.mu.Lock()
		s.client = fmt.Sprintf("%s %s, parent pid %d", p.ClientInfo.Name, p.ClientInfo.Version, os.Getppid())
		s.mu.Unlock()
		version := versions[0]
		for _, v := range versions {
			if v == p.ProtocolVersion {
				version = v
			}
		}
		resp.Result = map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "sshr", "version": s.opts.Version},
			"instructions":    "sshr holds the user's SSH hosts. Use list_hosts to find a host by name, upload_file to put a local file on a server (it is removed there after 15 minutes). Passwords and private keys are never returned.",
		}
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": s.tools()}
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			resp.Error = &rpcError{-32602, "invalid params"}
			break
		}
		result, err := s.call(p.Name, p.Arguments)
		if errors.Is(err, errUnknownTool) {
			resp.Error = &rpcError{-32602, err.Error()}
			break
		}
		if err != nil {
			// tool errors go back as results, so the assistant can read them
			result = toolResult{Content: []content{{Type: "text", Text: toolError(err)}}, IsError: true}
		}
		resp.Result = result
	default:
		resp.Error = &rpcError{-32601, "method not found: " + req.Method}
	}
	s.send(resp)
}

type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolResult struct {
	Content           []content `json:"content"`
	StructuredContent any       `json:"structuredContent,omitempty"`
	IsError           bool      `json:"isError,omitempty"`
}

var errUnknownTool = errors.New("unknown tool")

// toolError words the error codes of app for the assistant, it passes the
// text on to the user
func toolError(err error) string {
	if errors.Is(err, app.ErrAsksPassword) {
		return "this host asks for its password on every connect and there is no terminal to type it in, save its password in sshr or log in with a key"
	}
	// ssh errors carry the stderr and the banner of the server
	text, _ := dataText(err.Error())
	return text
}

func (s *server) tools() []map[string]any {
	hostArg := map[string]any{"type": "string", "description": "host name, address or ID as shown by list_hosts"}
	tools := []map[string]any{
		{
			"name":        "list_hosts",
			"description": "List the saved SSH hosts: name, address, user, port, how it logs in, jump hosts, session and port forwards. No passwords or keys.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
			"annotations": map[string]any{"readOnlyHint": true, "openWorldHint": false},
		},
		{
			"name":        "upload_file",
			"description": "Copy a local file to a saved host into ~/.cache/sshr/pasted/ and return its path on the server. The file is removed there after 15 minutes.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"host": hostArg,
					"path": map[string]any{"type": "string", "description": "absolute path of the local file"},
				},
				"required": []string{"host", "path"},
			},
			"annotations": map[string]any{"readOnlyHint": false, "destructiveHint": false, "openWorldHint": true},
		},
	}
	if s.opts.AllowCommands {
		tools = append(tools, map[string]any{
			"name":        "run_command",
			"description": "Run a shell command on a saved host without a terminal and return its output and exit code. Output is cut at 64 KiB per stream. Interactive programs do not work.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"host":            hostArg,
					"command":         map[string]any{"type": "string", "description": "command line, run with sh on the server"},
					"timeout_seconds": map[string]any{"type": "integer", "description": "stop the command after this many seconds, default 60, at most 600"},
				},
				"required": []string{"host", "command"},
			},
			"annotations": map[string]any{"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true},
		})
	}
	return tools
}

func (s *server) call(name string, raw json.RawMessage) (toolResult, error) {
	switch name {
	case "list_hosts":
		return s.listHosts()
	case "upload_file":
		var a struct{ Host, Path string }
		if err := json.Unmarshal(raw, &a); err != nil {
			return toolResult{}, err
		}
		s.slots <- struct{}{}
		defer func() { <-s.slots }()
		return s.uploadFile(a.Host, a.Path)
	case "run_command":
		if !s.opts.AllowCommands {
			return toolResult{}, errUnknownTool
		}
		var a struct {
			Host           string `json:"host"`
			Command        string `json:"command"`
			TimeoutSeconds int    `json:"timeout_seconds"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return toolResult{}, err
		}
		s.slots <- struct{}{}
		defer func() { <-s.slots }()
		return s.runCommand(a.Host, a.Command, a.TimeoutSeconds)
	}
	return toolResult{}, fmt.Errorf("%w %q", errUnknownTool, name)
}

func (s *server) listHosts() (toolResult, error) {
	hosts, err := s.store.List()
	if err != nil {
		return toolResult{}, err
	}
	out := make([]app.HostSummary, 0, len(hosts))
	for i := range hosts {
		out = append(out, dataSummary(hosts[i].Summary()))
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return toolResult{
		Content:           []content{{Type: "text", Text: hostsNote + "\n" + string(b)}},
		StructuredContent: map[string]any{"hosts": out, "note": hostsNote},
	}, nil
}

func (s *server) findHost(query string) (*app.Host, error) {
	h, err := s.store.Find(query)
	var amb *app.AmbiguousError
	switch {
	case errors.As(err, &amb):
		names := make([]string, len(amb.Hosts))
		for i, h := range amb.Hosts {
			id := h.ID
			if len(id) > 8 {
				id = id[:8]
			}
			names[i] = h.Name + " (" + id + ")"
		}
		return nil, fmt.Errorf("%q matches several hosts: %s, use the ID", query, strings.Join(names, ", "))
	case errors.Is(err, app.ErrNotFound):
		return nil, fmt.Errorf("no saved host %q, see list_hosts", query)
	}
	return h, err
}

// uploadMax keeps an assistant from pushing huge files through ssh by
// mistake
const uploadMax = 100 << 20

func (s *server) uploadFile(host, path string) (toolResult, error) {
	h, err := s.findHost(host)
	if err != nil {
		return toolResult{}, err
	}
	if !filepath.IsAbs(path) {
		return toolResult{}, errors.New("path must be absolute")
	}
	if err := checkUploadPath(path); err != nil {
		return toolResult{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return toolResult{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > uploadMax {
		return toolResult{}, fmt.Errorf("%s is not a regular file of at most %d MiB", path, uploadMax>>20)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return toolResult{}, err
	}
	ext := strings.TrimPrefix(filepath.Ext(path), ".")
	if ext == "" {
		ext = "bin"
	}
	end, err := s.begin("upload_file", h, "")
	if err != nil {
		return toolResult{}, err
	}
	remote, err := s.store.UploadImage(h, data, ext, true)
	end(exitOf(err), int64(len(data)), err)
	if err != nil {
		return toolResult{}, err
	}
	name, _ := dataText(h.Name)
	return toolResult{
		Content:           []content{{Type: "text", Text: remote}},
		StructuredContent: map[string]any{"host": name, "path": remote},
	}, nil
}

func (s *server) runCommand(host, command string, timeout int) (toolResult, error) {
	h, err := s.findHost(host)
	if err != nil {
		return toolResult{}, err
	}
	if strings.TrimSpace(command) == "" {
		return toolResult{}, errors.New("empty command")
	}
	if s.opts.CommandsAllowed != nil {
		if err := s.opts.CommandsAllowed(h); err != nil {
			return toolResult{}, err
		}
	}
	if timeout <= 0 {
		timeout = 60
	}
	if timeout > 600 {
		timeout = 600
	}
	// quoted, a carriage return or an escape sequence in the command cannot
	// rewrite lines in the log of the client
	fmt.Fprintf(logOut, "sshr mcp: run on %q: %q\n", h.Name, command)
	end, err := s.begin("run_command", h, command)
	if err != nil {
		return toolResult{}, err
	}
	res, err := s.store.RunRemote(h, command, nil, time.Duration(timeout)*time.Second)
	if err != nil {
		end(-1, 0, err)
		return toolResult{}, err
	}
	end(res.ExitCode, int64(len(res.Stdout)+len(res.Stderr)), nil)
	// the output is the remote host's, it reaches the model as data
	stdout, n1 := dataText(string(res.Stdout))
	stderr, n2 := dataText(string(res.Stderr))
	nonce := newNonce()
	text := fmt.Sprintf("exit code %d\n%s\n%s", res.ExitCode, fenced("stdout", stdout, nonce), fenced("stderr", stderr, nonce))
	if n := n1 + n2; n > 0 {
		text += fmt.Sprintf("\n(%d control characters and escape sequences removed)", n)
	}
	if res.Truncated {
		text += "\n(output cut at 64 KiB)"
	}
	name, _ := dataText(h.Name)
	return toolResult{
		Content: []content{{Type: "text", Text: text}},
		// clients hand structuredContent to the model too, it carries the
		// same markers
		StructuredContent: map[string]any{
			"host": name, "exit_code": res.ExitCode,
			"stdout": fenced("stdout", stdout, nonce), "stderr": fenced("stderr", stderr, nonce), "truncated": res.Truncated,
		},
		IsError: res.ExitCode != 0,
	}, nil
}

// checkUploadPath refuses files in hidden folders of the home folder and
// hidden files there, ~/.ssh keys, ~/.sshr tokens and sync state, cloud
// credentials, the path is resolved first so a link cannot point there
func checkUploadPath(path string) error {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	if h, err := filepath.EvalSymlinks(home); err == nil {
		home = h
	}
	rel, err := filepath.Rel(home, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if strings.HasPrefix(part, ".") {
			return fmt.Errorf("%s is hidden in the home folder (keys, tokens, settings), upload_file does not send such files, copy it elsewhere first if it is meant to go", path)
		}
	}
	return nil
}
