// Package audit keeps an append-only record of what assistants and scripts
// did through sshr mcp and sshr serve: which client, which host, which
// action and how it ended, never a secret, off by default
package audit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sshr.dev/internal/fileio"
)

// FileName is the log in the sshr directory, FileName+".1" is the one
// before it
const FileName = "audit.jsonl"

const (
	// DefaultMaxMB is the size the log reaches before it moves to .1
	DefaultMaxMB = 10
	// recordMax caps one line, a long command or error is cut to fit
	recordMax = 4 << 10
	lockWait  = 2 * time.Second
)

// Record is one line of the log, a start and an end share Req
type Record struct {
	TS       time.Time `json:"ts"`
	V        int       `json:"v"`
	PID      int       `json:"pid"`
	Surface  string    `json:"surface"`
	Client   string    `json:"client,omitempty"`
	Req      string    `json:"req"`
	Phase    string    `json:"phase"`
	Action   string    `json:"action"`
	HostID   string    `json:"host_id,omitempty"`
	HostName string    `json:"host_name,omitempty"`
	Target   string    `json:"target,omitempty"`
	// CmdLen, CmdProg and CmdHMAC stand for a command, the first word and a
	// keyed hash tell two commands apart without keeping a password typed
	// into one, Cmd holds the whole command only when asked for
	CmdLen  int    `json:"cmd_len,omitempty"`
	CmdProg string `json:"cmd_prog,omitempty"`
	CmdHMAC string `json:"cmd_hmac,omitempty"`
	Cmd     string `json:"cmd,omitempty"`
	Exit    *int   `json:"exit,omitempty"`
	DurMS   int64  `json:"dur_ms,omitempty"`
	Bytes   int64  `json:"bytes,omitempty"`
	Err     string `json:"err,omitempty"`

	// Command is the command of the action, Begin turns it into the fields
	// above
	Command string `json:"-"`
}

// Log writes the audit log, a nil *Log writes nothing
type Log struct {
	path     string
	maxBytes int64
	full     bool
	key      []byte
	// Warn gets the end records that could not be written
	Warn io.Writer
}

// Open prepares the log in dir, maxMB of 0 means DefaultMaxMB, full keeps
// whole commands instead of their hash
func Open(dir string, maxMB int, full bool) (*Log, error) {
	if maxMB <= 0 {
		maxMB = DefaultMaxMB
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	l := &Log{path: filepath.Join(dir, FileName), maxBytes: int64(maxMB) << 20, full: full, Warn: os.Stderr}
	key, err := loadKey(filepath.Join(dir, "audit.key"), l.path+".lock")
	if err != nil {
		return nil, fmt.Errorf("audit log: %v", err)
	}
	l.key = key
	return l, nil
}

// loadKey reads the key of the command hashes or makes it once
func loadKey(path, lock string) ([]byte, error) {
	unlock, err := fileio.WaitLock(lock, "writing the audit log", lockWait)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if b, err := fileio.ReadFileShared(path); err == nil {
		if key, err := hex.DecodeString(strings.TrimSpace(string(b))); err == nil && len(key) == 32 {
			return key, nil
		}
		return nil, errors.New(path + " is damaged, remove it to start a new key")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, fileio.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600)
}

// Begin writes the start record of an action and returns what writes its
// end, an action that changes something does not run when the start
// cannot be written
func (l *Log) Begin(r Record) (func(exit int, bytes int64, err error), error) {
	if l == nil {
		return func(int, int64, error) {}, nil
	}
	var id [8]byte
	rand.Read(id[:])
	r.Req, r.V, r.PID, r.Phase = hex.EncodeToString(id[:]), 1, os.Getpid(), "start"
	if r.Command != "" {
		if l.full {
			r.Cmd = r.Command
		} else {
			r.CmdLen = len(r.Command)
			if f := strings.Fields(r.Command); len(f) > 0 {
				r.CmdProg = f[0]
			}
			m := hmac.New(sha256.New, l.key)
			m.Write([]byte(r.Command))
			r.CmdHMAC = hex.EncodeToString(m.Sum(nil))[:32]
		}
	}
	started := time.Now()
	r.TS = started.UTC()
	if err := l.write(r); err != nil {
		return nil, fmt.Errorf("audit log %s: %v", l.path, err)
	}
	return func(exit int, bytes int64, err error) {
		e := Record{TS: time.Now().UTC(), V: 1, PID: r.PID, Surface: r.Surface, Client: r.Client, Req: r.Req,
			Phase: "end", Action: r.Action, HostID: r.HostID, HostName: r.HostName,
			Exit: &exit, DurMS: time.Since(started).Milliseconds(), Bytes: bytes}
		if err != nil {
			e.Err = err.Error()
		}
		if werr := l.write(e); werr != nil && l.Warn != nil {
			fmt.Fprintf(l.Warn, "sshr: the end of %s on %q is not in the audit log: %v\n", r.Action, r.HostName, werr)
		}
	}, nil
}

// write appends one line under the lock, moving a full log to .1 first,
// two processes never interleave their lines
func (l *Log) write(r Record) error {
	line, err := encode(r)
	if err != nil {
		return err
	}
	unlock, err := fileio.WaitLock(l.path+".lock", "writing the audit log", lockWait)
	if err != nil {
		return err
	}
	defer unlock()
	if fi, err := os.Stat(l.path); err == nil && fi.Size()+int64(len(line)) > l.maxBytes {
		// a rename that fails (a scanner holds the file on Windows) leaves
		// the log a bit longer, the record still goes in
		os.Rename(l.path, l.path+".1")
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(line)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// encode makes the line of r, the free text fields are cut until it fits
// in recordMax, encoding/json escapes control characters so a line cannot
// be forged
func encode(r Record) ([]byte, error) {
	for {
		b, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		if len(b) < recordMax {
			return append(b, '\n'), nil
		}
		longest := &r.Cmd
		for _, s := range []*string{&r.Err, &r.HostName, &r.Client, &r.Target} {
			if len(*s) > len(*longest) {
				longest = s
			}
		}
		if len(*longest) == 0 {
			return nil, errors.New("record too long")
		}
		if len(*longest) <= 16 {
			*longest = ""
		} else {
			*longest = strings.ToValidUTF8((*longest)[:len(*longest)/2], "") + "..."
		}
	}
}
