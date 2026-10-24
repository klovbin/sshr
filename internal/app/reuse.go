package app

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

var reuseWarnOnce sync.Once

// ControlPersist is how long a master connection stays up after its last
// session closes
const ControlPersist = "10m"

// socketPathMax keeps ControlPath under the unix socket path limit, 104
// bytes on macOS and 108 on Linux, %C expands to 40 hex characters
const socketPathMax = 100

// ControlDir is where master connection sockets live, 0700 because anyone
// who can open a socket there gets a session without logging in, it is
// $XDG_RUNTIME_DIR/sshr when there is one (short, per user, gone on logout)
// and ~/.sshr/cm otherwise, a path too long for a socket is an error
func ControlDir() (string, error) {
	var dirs []string
	if rt := os.Getenv("XDG_RUNTIME_DIR"); rt != "" {
		dirs = append(dirs, filepath.Join(rt, "sshr"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".sshr", "cm"))
	}
	for _, dir := range dirs {
		if len(dir)+1+40 >= socketPathMax {
			continue
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			continue
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			continue
		}
		return dir, nil
	}
	return "", errors.New("no directory with a path short enough for ssh control sockets")
}

// reuseOn tells whether connections should share a master, the CLI flags
// set e.Reuse and SSHR_REUSE for jump hops, otherwise the setting decides
func (e sshEnv) reuseOn() bool {
	if e.Reuse != nil {
		return *e.Reuse
	}
	if v, err := strconv.ParseBool(os.Getenv("SSHR_REUSE")); err == nil {
		return v
	}
	st, _ := LoadSettings()
	return st.Reuse
}

// reuseArgs returns the ControlMaster options for h, or nil when reuse is
// off, on Windows (its OpenSSH has no ControlMaster) and when the user's own
// ssh config already sets ControlMaster for this host, then theirs is used
func (e sshEnv) reuseArgs(h *Host) []string {
	if runtime.GOOS == "windows" || !e.reuseOn() {
		return nil
	}
	if userControlMaster(h) {
		return nil
	}
	dir, err := ControlDir()
	if err != nil {
		reuseWarnOnce.Do(func() {
			fmt.Fprintf(os.Stderr, "sshr: connection reuse is off for now: %v\n", err)
		})
		return nil
	}
	return []string{
		"-o", "ControlMaster=auto",
		// %C is a hash of the connection, short enough for the unix socket
		// path limit
		"-o", "ControlPath=" + filepath.Join(dir, "%C"),
		"-o", "ControlPersist=" + ControlPersist,
	}
}

// userControlMaster asks ssh how it would connect to h (ssh -G, nothing is
// sent over the network) and reports whether ssh config turns on
// ControlMaster for it
func userControlMaster(h *Host) bool {
	out, err := sshCommand("-G", "-p", strconv.Itoa(h.Port), "--", h.Dest()).Output()
	if err != nil {
		return false
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "controlmaster "); ok {
			return v != "false"
		}
	}
	return false
}

// CloseMaster stops the master connection to h, if there is one
func (e sshEnv) CloseMaster(h *Host) error {
	if runtime.GOOS == "windows" {
		return errors.New("connection reuse is not available on Windows")
	}
	dir, err := ControlDir()
	if err != nil {
		return err
	}
	cmd := sshCommand("-o", "ControlPath="+filepath.Join(dir, "%C"),
		"-p", strconv.Itoa(h.Port), "-O", "exit", "--", h.Dest())
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "No such file") {
			return fmt.Errorf("no shared connection to %s is open", h.Name)
		}
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return errors.New(msg)
	}
	return nil
}
