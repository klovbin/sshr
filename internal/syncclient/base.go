package syncclient

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"sshr.dev/internal/fileio"
)

// The base of a host is the version this device last synced, sealed as it
// is on the server, a host changed here and on another device is merged
// field by field against it (hosts.MergeThreeWay), without it the change of
// one side becomes a conflict copy, files are named by the hash of the
// blob, so a blob downloaded and not taken does not replace the base
type baseFile struct {
	Epoch int    `json:"epoch"`
	Blob  []byte `json:"blob"`
}

func (c *Client) baseDir() string { return filepath.Join(c.Dir, "base") }

// validHash is a hash blobHash makes, a manifest is signed but the names it
// carries must not reach a path unchecked
func validHash(h string) bool {
	b, err := hex.DecodeString(h)
	return err == nil && len(b) == 32
}

// keepBase writes a blob that was sent or received, a failure only costs
// the merge of a later conflict
func (c *Client) keepBase(epoch int, blob []byte) {
	h := blobHash(blob)
	b, err := json.Marshal(baseFile{Epoch: epoch, Blob: blob})
	if err == nil {
		err = os.MkdirAll(c.baseDir(), 0o700)
	}
	if err == nil {
		err = fileio.WriteFile(filepath.Join(c.baseDir(), h), b, 0o600)
	}
	if err != nil {
		c.logf("could not keep the synced version of a host, a later conflict on it gives a copy: %v", err)
	}
}

// basePayload opens the base of entry id with blob hash h, nil when there
// is none, it does not match or its key is gone
// keptBlob is the sealed blob h as this device keeps it for merges, nil
// when it is not kept or does not match its hash
func (c *Client) keptBlob(h string) []byte {
	if !validHash(h) {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(c.baseDir(), h))
	if err != nil {
		return nil
	}
	var f baseFile
	if json.Unmarshal(b, &f) != nil || blobHash(f.Blob) != h {
		return nil
	}
	return f.Blob
}

func (c *Client) basePayload(id, h string) *payload {
	if !validHash(h) {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(c.baseDir(), h))
	if err != nil {
		return nil
	}
	var f baseFile
	if json.Unmarshal(b, &f) != nil || blobHash(f.Blob) != h {
		return nil
	}
	key, err := c.vaultKey(f.Epoch)
	if err != nil {
		return nil
	}
	plain, err := openEntry(key, c.st.Account, id, f.Epoch, f.Blob)
	if err != nil {
		return nil
	}
	p, err := parsePayload(id, plain)
	if err != nil {
		return nil
	}
	return p
}

// pruneBase removes the bases no entry points to any more
func (c *Client) pruneBase() {
	names, err := os.ReadDir(c.baseDir())
	if err != nil {
		return
	}
	keep := map[string]bool{}
	for _, e := range c.st.Entries {
		keep[e.Blob], keep[e.base()] = true, true
	}
	// a push the store may still lose goes back to these, a merge after
	// that needs the versions both sides started from
	if u := c.st.Unconfirmed; u != nil {
		for _, e := range u.Entries {
			keep[e.Blob], keep[e.base()] = true, true
		}
	}
	for _, n := range names {
		if !keep[n.Name()] {
			os.Remove(filepath.Join(c.baseDir(), n.Name()))
		}
	}
}

// keepUploaded makes sure the blobs a push uploaded are in an object store
// after its manifest went in, a cleanup of the store may have taken one
// the push uploaded before a sleep of the machine, the head names it now,
// so it goes back from the base kept here, a store that cannot put it back
// is said, the other devices skip that host until it changes again
func (c *Client) keepUploaded(hashes []string) {
	ob, ok := c.backend().(ObjectBackend)
	if !ok {
		return
	}
	for _, h := range hashes {
		// one more try rides out a request the network dropped
		var err error
		for try := 0; try < 2; try++ {
			if err = c.keepBlob(ob, h); err == nil {
				break
			}
		}
		if err != nil {
			c.logf("WARNING: a blob of this push may be missing from the store (%v), the other devices skip that host until it is edited again", err)
		}
	}
}

// keepBlob puts blob h back when the store lacks it
func (c *Client) keepBlob(ob ObjectBackend, h string) error {
	have, err := ob.hasBlob(h)
	if err != nil || have {
		return err
	}
	blob := c.keptBlob(h)
	if blob == nil {
		return errors.New("this device does not keep it")
	}
	return ob.PutBlob(h, blob)
}
