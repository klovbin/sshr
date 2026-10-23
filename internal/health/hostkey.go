package health

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"sshr.dev/internal/hosts"
)

// Host key states against the user's known_hosts
const (
	// KeyKnown means known_hosts has this key for the host
	KeyKnown = "known"
	// KeyChanged means known_hosts has another key for the host, the
	// server was reinstalled or someone is in between
	KeyChanged = "changed"
	// KeyUnknown means known_hosts has no key for the host yet
	KeyUnknown = "unknown"
)

// HostKey is what the server showed as its key
type HostKey struct {
	Fingerprint string
	Type        string
	State       string
	Err         string
}

var errGotKey = errors.New("host key read")

// CheckHostKey runs the SSH key exchange with the host to read its key and
// stops before any login, the key is compared with ~/.ssh/known_hosts, a
// host behind a jump host is not checked
func CheckHostKey(h *hosts.Host) HostKey {
	if h.Jump != "" {
		return HostKey{Err: "reached through " + h.Jump}
	}
	port := hosts.EffectivePort(h.Port)
	addr := net.JoinHostPort(strings.Trim(h.Host, "[]"), strconv.Itoa(port))
	var got ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User:    h.User,
		Timeout: HealthTimeout,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return errGotKey
		},
	}
	conn, err := net.DialTimeout("tcp", addr, HealthTimeout)
	if err != nil {
		return HostKey{Err: shortNetErr(err)}
	}
	conn.SetDeadline(time.Now().Add(2 * HealthTimeout))
	c, _, _, err := ssh.NewClientConn(conn, addr, cfg)
	if c != nil {
		c.Close()
	}
	conn.Close()
	if got == nil {
		if err == nil {
			err = errors.New("no key")
		}
		return HostKey{Err: err.Error()}
	}
	return HostKey{Fingerprint: ssh.FingerprintSHA256(got), Type: got.Type(), State: knownState(addr, got)}
}

// knownState looks the key up in the user's known_hosts files the way ssh
// names the host, [host]:port for a port other than 22
func knownState(addr string, key ssh.PublicKey) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return KeyUnknown
	}
	var files []string
	for _, f := range []string{"known_hosts", "known_hosts2"} {
		if p := filepath.Join(home, ".ssh", f); isFile(p) {
			files = append(files, p)
		}
	}
	if len(files) == 0 {
		return KeyUnknown
	}
	check, err := knownhosts.New(files...)
	if err != nil {
		return KeyUnknown
	}
	remote, _ := net.ResolveTCPAddr("tcp", addr)
	err = check(addr, remote, key)
	var ke *knownhosts.KeyError
	switch {
	case err == nil:
		return KeyKnown
	case errors.As(err, &ke) && len(ke.Want) > 0:
		return KeyChanged
	}
	return KeyUnknown
}

// CheckHostKeyAll reads the keys of hosts eight at a time, keyed by host ID
func CheckHostKeyAll(list []hosts.Host) map[string]HostKey {
	out := make(map[string]HostKey, len(list))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i := range list {
		h := &list[i]
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			k := CheckHostKey(h)
			mu.Lock()
			out[h.ID] = k
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

// isFile tells whether p is a file that exists
func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
