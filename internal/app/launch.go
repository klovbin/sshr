package app

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// LaunchOptions say what a session to a host opens
type LaunchOptions struct {
	// Forwards are added as -L, -R and -D
	Forwards []Forward
	// Mosh tries mosh first, the plan falls back to ssh where mosh cannot go
	Mosh bool
	// Plain opens a plain shell even when the host attaches to tmux or zellij
	Plain bool
	// Tunnel opens the forwards only, no shell (ssh -N), and fails when a
	// port is taken
	Tunnel bool
	// Batch is for a session with no terminal to ask in: a host that asks
	// for its password every time is refused, ssh never prompts, a tunnel
	// keeps itself alive
	Batch bool
}

// SessionPlan is how a session to a host starts, the caller runs it, waits
// for it and prints its notes
type SessionPlan struct {
	// Host is a copy of the host with its route decided, the caller's host
	// is not written, the app may share it between goroutines
	Host Host
	// Tool is "ssh" or "mosh", looked up on PATH when the command is made
	Tool string
	Args []string
	// Via is the jump spec the session goes through, empty for a direct one
	Via string
	// Session is the tmux or zellij session it attaches to, empty for none
	Session string
	// Notes say why the plan differs from what was asked, in the order they
	// apply, "mosh cannot forward ports, using ssh" and the like
	Notes []string
	// Fallback is the ssh plan to run when mosh does not start, built from
	// the same options, the route is not checked again
	Fallback *SessionPlan
	batch    bool
}

// moshStartup is how long a failing mosh run still counts as "could not
// start" (no mosh-server, UDP blocked) rather than a session that ended
const moshStartup = 20 * time.Second

// MoshStartFailed tells whether a mosh run that ended with code after
// elapsed did not start, then the Fallback runs instead
func MoshStartFailed(code int, elapsed time.Duration) bool {
	return code != 0 && elapsed < moshStartup
}

// PlanSession builds the command line of a session to h with the options
// of o, it checks a host with a gateway once, on a copy of h
func (s *Store) PlanSession(h *Host, o LaunchOptions) (*SessionPlan, error) {
	if o.Batch && h.PasswordMode == PasswordAsk {
		return nil, ErrAsksPassword
	}
	hc := *h
	opts, err := s.ConnectArgs(&hc)
	if err != nil {
		return nil, err
	}
	if o.Batch && !hc.PasswordFromSshr() {
		opts = append(opts, "-o", "BatchMode=yes")
	}
	session := hc.Session
	if o.Plain || o.Tunnel {
		session = ""
	}
	p := &SessionPlan{Host: hc, Tool: "ssh", Via: hc.Via(), Session: session, batch: o.Batch}
	dest := hc.Dest()
	sshOpts := opts
	if o.Tunnel {
		// without it ssh keeps running when a port is taken, and the tunnel
		// silently does nothing
		opts = append(opts, "-N", "-o", "ExitOnForwardFailure=yes")
		if o.Batch {
			opts = append(opts, "-o", "ServerAliveInterval=30")
		}
	}
	for _, f := range o.Forwards {
		opts = append(opts, f.Args()...)
	}
	switch {
	case o.Tunnel:
		p.Args = append(opts, "--", dest)
	case session != "":
		// a remote command gets no terminal unless asked, and tmux or zellij
		// need one
		p.Args = append(opts, "-t", "--", dest, SessionCommand(session))
	default:
		p.Args = append(opts, "--", dest)
	}
	if !o.Mosh || o.Tunnel {
		return p, nil
	}
	if note := moshRefusal(o, p.Via, sshOpts); note != "" {
		p.Notes = append(p.Notes, note)
		return p, nil
	}
	m := &SessionPlan{Host: hc, Tool: "mosh", Via: p.Via, Session: session, Fallback: p, batch: o.Batch}
	m.Args = []string{"--ssh=ssh " + strings.Join(sshOpts, " "), "--", dest}
	if script := SessionScript(session); script != "" {
		// mosh-server runs the command itself, without a shell in between
		m.Args = append(m.Args, "sh", "-c", script)
	}
	return m, nil
}

// moshRefusal is why mosh cannot carry this session, empty when it can
func moshRefusal(o LaunchOptions, via string, sshOpts []string) string {
	if len(o.Forwards) > 0 {
		return "mosh cannot forward ports, using ssh"
	}
	// mosh needs a direct UDP path to the server, which a bastion does not
	// give, and its --ssh cannot carry a quoted ProxyCommand
	if via != "" {
		return "mosh does not work through jump hosts, using ssh"
	}
	if _, err := exec.LookPath("mosh"); err != nil {
		return "mosh is not installed, using ssh"
	}
	// mosh splits --ssh on whitespace, any option with a space (a key or
	// agent path, the sshr path in ProxyCommand) would be cut in two
	for _, opt := range sshOpts {
		if strings.ContainsAny(opt, " \t") {
			return "the ssh option " + strconv.Quote(opt) + " has spaces, mosh cannot pass it, using ssh"
		}
	}
	return ""
}

// Command makes the process of the plan with the secrets of the host
// attached, it is not started, so the caller can set its output, the
// returned cleanup runs after the process ends
func (p *SessionPlan) Command() (*exec.Cmd, func(), error) {
	path, err := exec.LookPath(p.Tool)
	if err != nil {
		return nil, func() {}, errors.New(p.Tool + " not found in PATH")
	}
	cmd := exec.Command(path, p.Args...)
	if p.batch {
		// the environment goes first, AttachAuth adds the askpass to it,
		// jump hops started as separate ssh processes read it too
		cmd.Env = append(os.Environ(), "SSHR_BATCH=1")
	}
	cleanup, err := AttachAuth(cmd, &p.Host)
	if err != nil {
		return nil, func() {}, err
	}
	return cmd, cleanup, nil
}
