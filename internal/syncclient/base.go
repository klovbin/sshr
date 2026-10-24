package syncclient

import (
	"encoding/hex"
	"encoding/json"
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
		keep[e.Blob] = true
	}
	for _, n := range names {
		if !keep[n.Name()] {
			os.Remove(filepath.Join(c.baseDir(), n.Name()))
		}
	}
}
