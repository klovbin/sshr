package syncclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sshr.dev/internal/fileio"
	"sshr.dev/internal/syncproto"
)

// cleanupGrace is how long a blob no change names stays before a cleanup
// deletes it, a push uploads its blobs before its manifest, a blob first
// seen as an orphan a day ago is no push still running
const cleanupGrace = 24 * time.Hour

// cleanupWindow is how many changes before the head still count as live,
// a device that read the head before the last few changes fetches their
// blobs on its next try
const cleanupWindow = 10

// ErrServerCleans means the account is on sshr-sync, which deletes the
// blobs no change names by itself
var ErrServerCleans = errors.New("the sync server deletes the blobs no change names by itself, a day after their upload")

// CleanupReport is what one cleanup found and did
type CleanupReport struct {
	// Blobs is how many blobs the store holds, Orphans how many of them no
	// live change names
	Blobs, Orphans int
	// Due are the orphans first seen at least cleanupGrace ago, Deleted
	// how many of them went
	Due, Deleted int
}

// cleanupSeen is the journal of a cleanup on this device: when each orphan
// was first seen, a blob goes only on a run at least cleanupGrace later
type cleanupSeen struct {
	Account string               `json:"account"`
	LastRun time.Time            `json:"last_run"`
	Seen    map[string]time.Time `json:"seen"`
}

func (c *Client) cleanupSeenPath() string { return filepath.Join(c.Dir, "cleanup-seen.json") }

// Cleanup deletes the blobs of an object store that no live change names
// and that this device saw as orphans at least a day ago, only with apply,
// without it it only counts them and notes the orphans it sees
func (c *Client) Cleanup(apply bool) (CleanupReport, error) {
	var r CleanupReport
	err := c.run(func() error {
		var err error
		r, err = c.cleanup(apply, time.Now())
		return err
	})
	return r, err
}

func (c *Client) cleanup(apply bool, now time.Time) (CleanupReport, error) {
	var r CleanupReport
	if err := c.load(); err != nil {
		return r, err
	}
	ob, ok := c.backend().(ObjectBackend)
	if !ok {
		return r, ErrServerCleans
	}
	if err := c.pull(); err != nil {
		return r, err
	}
	// a push or a key change of this device that is not settled names
	// blobs no head lists yet
	if c.st.Unconfirmed != nil || c.st.Rotation != nil {
		return r, errors.New("a change of this device is not settled yet, run sshr sync first")
	}
	if err := ob.checkConflicts(); err != nil {
		return r, err
	}
	names, err := ob.Store.List(objBlobs)
	if err != nil {
		return r, fmt.Errorf("listing the blobs: %w", err)
	}
	r.Blobs = len(names)
	inStore := make(map[string]bool, len(names))
	for _, n := range names {
		// a temp file of a sync tool or a name no push makes is no blob
		if h := strings.TrimPrefix(n, objBlobs); checkHash(h) == nil {
			inStore[h] = true
		}
	}
	head := c.headBlobs()
	// a listing that misses a blob the head names is not the whole store,
	// what it misses cannot be told from what is gone
	for h, id := range head {
		if !inStore[h] {
			return r, fmt.Errorf("the listing of the store misses the blob of host %s, either the listing is short or the store lost it, nothing is deleted, try again later, a lost blob comes back when the host is edited on a device that has it", short(id, 8))
		}
	}
	live, err := c.liveBlobs(ob, head)
	if err != nil {
		return r, err
	}
	seen := c.readCleanupSeen(now)
	next := cleanupSeen{Account: c.st.Account, LastRun: now, Seen: map[string]time.Time{}}
	var due []string
	for h := range inStore {
		if live[h] {
			continue
		}
		r.Orphans++
		first, ok := seen.Seen[h]
		if !ok {
			first = now
		}
		next.Seen[h] = first
		if now.Sub(first) >= cleanupGrace {
			due = append(due, h)
		}
	}
	r.Due = len(due)
	if apply && len(due) > 0 {
		for _, h := range due {
			// a change pushed meanwhile may name a blob the listing took
			// for an orphan, the next change showing up stops the run
			// before every delete, a late push then puts its blob back
			if _, err := ob.Store.Get(manifestName(c.st.Counter+1), 0); !errors.Is(err, ErrNotFound) {
				c.writeCleanupSeen(next)
				if err != nil && !errors.Is(err, ErrTooLarge) {
					return r, err
				}
				return r, errors.New("the account changed during the cleanup, it stopped, run it again")
			}
			if err := ob.Store.Delete(objBlobs + h); err != nil {
				c.writeCleanupSeen(next)
				return r, fmt.Errorf("deleting blob %s: %w", short(h, 12), err)
			}
			delete(next.Seen, h)
			r.Deleted++
		}
	}
	if err := c.writeCleanupSeen(next); err != nil {
		return r, err
	}
	return r, nil
}

// headBlobs are the blobs of the head this device applied and the hosts
// they belong to
func (c *Client) headBlobs() map[string]string {
	out := map[string]string{}
	for id, e := range c.st.Entries {
		if !e.Deleted && e.Blob != "" {
			out[e.Blob] = id
		}
	}
	for id, e := range c.st.Skipped {
		if !e.Deleted && e.Hash != "" {
			out[e.Hash] = id
		}
	}
	return out
}

// liveBlobs are the blobs of the head and of the cleanupWindow changes
// before it, of every kept change on a synced folder, whose undo of a
// forked push goes back further
func (c *Client) liveBlobs(ob ObjectBackend, head map[string]string) (map[string]bool, error) {
	live := make(map[string]bool, len(head))
	for h := range head {
		live[h] = true
	}
	counters, err := ob.manifests()
	if err != nil {
		return nil, err
	}
	if !c.weakStore() && len(counters) > cleanupWindow+1 {
		counters = counters[len(counters)-cleanupWindow-1:]
	}
	for _, n := range counters {
		raw, err := ob.Store.Get(manifestName(n), syncproto.MaxManifest)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		// a change that does not read adds nothing, it can only keep more,
		// a change of a newer format may name its blobs elsewhere
		var sm syncproto.Signed
		var m syncproto.Manifest
		if json.Unmarshal(raw, &sm) != nil || json.Unmarshal(sm.Body, &m) != nil {
			continue
		}
		if m.Version > syncproto.FormatVersion {
			return nil, checkFormat(m.Version)
		}
		for _, e := range m.Entries {
			if e.Hash != "" {
				live[e.Hash] = true
			}
		}
	}
	return live, nil
}

// readCleanupSeen is the journal of this account, an empty one when it is
// missing, damaged, of another account or written later than now by the
// clock of this machine, a clock set back must not make a blob look older
func (c *Client) readCleanupSeen(now time.Time) cleanupSeen {
	b, err := os.ReadFile(c.cleanupSeenPath())
	var s cleanupSeen
	if err != nil || json.Unmarshal(b, &s) != nil || s.Account != c.st.Account || now.Before(s.LastRun) {
		return cleanupSeen{}
	}
	for h, t := range s.Seen {
		if now.Before(t) {
			delete(s.Seen, h)
		}
	}
	return s
}

func (c *Client) writeCleanupSeen(s cleanupSeen) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return fileio.WriteFile(c.cleanupSeenPath(), b, 0o600)
}
