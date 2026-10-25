package syncclient

import (
	"encoding/json"
	"os"
	"path/filepath"

	"sshr.dev/internal/fileio"
)

// leftEdits is what leave keeps of the hosts changed here since the last
// sync, a join of the same account takes them as seen, so the first pull
// merges the edit or keeps it as a conflict copy instead of writing the
// version of the account over it (#382)
type leftEdits struct {
	Account string                `json:"account"`
	Entries map[string]entryState `json:"entries"`
}

func (c *Client) leftEditsPath() string { return filepath.Join(c.Dir, "left-edits.json") }

// keepEdits writes leftEdits before leave forgets the device key, the hash
// of a host as it was synced is keyed with that key and means nothing
// after a join, an entry kept without it reads as changed here, a host
// removed here is not kept, after the join it comes back from the account
// instead of being removed on every device
func (c *Client) keepEdits() error {
	if err := c.loadLocal(); err != nil {
		return err
	}
	local, broken, err := c.localHosts()
	if err != nil {
		return err
	}
	kept := map[string]entryState{}
	for id, known := range c.st.Entries {
		plain, ok := local[id]
		if _, bad := broken[id]; bad || !ok || c.localHash(plain) == known.Local {
			continue
		}
		known.Local = ""
		kept[id] = known
	}
	if len(kept) == 0 {
		if err := os.Remove(c.leftEditsPath()); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	b, err := json.Marshal(leftEdits{Account: c.st.Account, Entries: kept})
	if err != nil {
		return err
	}
	if err := fileio.WriteFile(c.leftEditsPath(), b, 0o600); err != nil {
		return err
	}
	c.logf("%d hosts changed here since the last sync, a join of this account again keeps the changes", len(kept))
	return nil
}

// takeLeftEdits puts the entries leave kept into the state of a join of
// the same account, true when it did
func (c *Client) takeLeftEdits() bool {
	b, err := os.ReadFile(c.leftEditsPath())
	if os.IsNotExist(err) {
		return false
	}
	var le leftEdits
	if err == nil {
		err = json.Unmarshal(b, &le)
	}
	if err != nil {
		c.logf("%s does not read (%v), the hosts changed here before leave are not kept", c.leftEditsPath(), err)
		return false
	}
	if le.Account != c.st.Account {
		return false
	}
	for id, e := range le.Entries {
		c.st.Entries[id] = e
	}
	return true
}
