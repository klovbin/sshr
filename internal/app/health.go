package app

import (
	"bufio"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Health states of a host
const (
	// HealthUp means the port answered with an SSH banner
	HealthUp = "up"
	// HealthDown means the port did not answer, refused or the name does
	// not resolve
	HealthDown = "down"
	// HealthNotSSH means the port is open but sends no SSH banner
	HealthNotSSH = "not_ssh"
	// HealthUnknown means sshr cannot check this host from here, it is
	// reached through a jump host or ssh config
	HealthUnknown = "unknown"
)

// HealthTimeout bounds one check, the connect and the banner each
const HealthTimeout = 3 * time.Second

// DefaultHealthInterval is how often the app checks the hosts when the
// check is on and the interval is not set
const DefaultHealthInterval = 5 * time.Minute

// Health is the result of one check
type Health struct {
	State string
	// Latency is the time the TCP connect took, a round trip to the server
	Latency time.Duration
	// Reason says why the host is down, not SSH or unknown
	Reason string
	// Cause is the reason as a word for programs: dns, refused, timeout,
	// unreachable, no_banner, jump, alias or other
	Cause string
	At    time.Time
}

// CheckHealth opens a TCP connection to the host and reads the SSH banner,
// nothing is sent, no login is tried, sshd still logs the connection as
// closed before authentication
func CheckHealth(h *Host) Health {
	now := time.Now()
	if h.Jump != "" {
		return Health{State: HealthUnknown, Reason: "reached through " + h.Jump, Cause: "jump", At: now}
	}
	port := h.Port
	if port == 0 {
		port = 22
	}
	start := time.Now()
	c, err := net.DialTimeout("tcp", net.JoinHostPort(strings.Trim(h.Host, "[]"), strconv.Itoa(port)), HealthTimeout)
	if err != nil {
		var dns *net.DNSError
		if errors.As(err, &dns) && h.Host == h.Name {
			// an alias of ssh config (ProxyCommand), only ssh knows where it goes
			return Health{State: HealthUnknown, Reason: "an alias of ssh config", Cause: "alias", At: now}
		}
		return Health{State: HealthDown, Reason: shortNetErr(err), Cause: netCause(err), At: now}
	}
	lat := time.Since(start)
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(HealthTimeout))
	// servers may send lines before the banner, RFC 4253 4.2
	r := bufio.NewReaderSize(c, 256)
	for range 5 {
		line, err := r.ReadString('\n')
		if strings.HasPrefix(line, "SSH-") {
			return Health{State: HealthUp, Latency: lat, At: now}
		}
		if err != nil {
			break
		}
	}
	return Health{State: HealthNotSSH, Latency: lat, Reason: "the port answers without an SSH banner", Cause: "no_banner", At: now}
}

// netCause sorts a failed connect into a few causes a program can act on
func netCause(err error) string {
	var dns *net.DNSError
	switch {
	case errors.As(err, &dns):
		return "dns"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "unreachable"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	// Windows reports its own WSA codes, which the syscall constants above
	// do not match, its messages say the same
	switch msg := strings.ToLower(err.Error()); {
	case strings.Contains(msg, "refused"):
		return "refused"
	case strings.Contains(msg, "unreachable"):
		return "unreachable"
	}
	return "other"
}

// shortNetErr drops the "dial tcp 1.2.3.4:22: " prefix
func shortNetErr(err error) string {
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		var dns *net.DNSError
		if errors.As(op.Err, &dns) {
			return "the name does not resolve"
		}
		if op.Timeout() {
			return "no answer in " + HealthTimeout.String()
		}
		msg := op.Err.Error()
		if i := strings.LastIndex(msg, ": "); i >= 0 {
			msg = msg[i+2:]
		}
		return msg
	}
	return err.Error()
}

// CheckHealthAll checks the hosts eight at a time, the result is keyed by
// host ID
func CheckHealthAll(hosts []Host) map[string]Health {
	out := make(map[string]Health, len(hosts))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i := range hosts {
		h := &hosts[i]
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			r := CheckHealth(h)
			mu.Lock()
			out[h.ID] = r
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

// Label is the short text of a result, "23 ms", "down" and so on
func (r Health) Label() string {
	switch r.State {
	case HealthUp:
		ms := r.Latency.Milliseconds()
		if ms < 1 {
			return "<1 ms"
		}
		return strconv.FormatInt(ms, 10) + " ms"
	case HealthNotSSH:
		return "not ssh"
	}
	return r.State
}
