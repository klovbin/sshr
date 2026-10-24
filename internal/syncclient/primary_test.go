package syncclient

import (
	"crypto/rand"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"sshr.dev/internal/syncproto"
	"sshr.dev/internal/vault"
)

// forgePush writes the next manifest as device c would sign it, with edit
// applied to a copy of the head, the way a stolen device with a changed
// sshr could, it skips every check of the client
func forgePush(t *testing.T, c *Client, edit func(*syncproto.Manifest)) {
	t.Helper()
	must(t, c.load())
	_, raw, err := c.backend().Head()
	must(t, err)
	var sm syncproto.Signed
	must(t, json.Unmarshal(raw, &sm))
	var m syncproto.Manifest
	must(t, json.Unmarshal(sm.Body, &m))
	m.Counter, m.Prev = m.Counter+1, syncproto.BodyHash(sm.Body)
	edit(&m)
	key, err := c.vaultKey(m.Epoch)
	must(t, err)
	b, _, err := c.keys.signManifest(&m, key, c.st.DeviceID)
	must(t, err)
	must(t, c.backend().PutManifest(m.Counter-1, b))
}

// TestPrimaryDevice checks that the device that made the account is its
// primary device and that only it adds and removes devices (#292)
func TestPrimaryDevice(t *testing.T) {
	w := newWorld(t)
	w.pair()
	if w.a.st.Primary != w.a.st.DeviceID || w.b.st.Primary != w.a.st.DeviceID {
		t.Fatalf("primary on a %q, on b %q, a is %q", w.a.st.Primary, w.b.st.Primary, w.a.st.DeviceID)
	}
	_, err := w.b.RemoveDevice(w.a.st.DeviceID[:8])
	if err == nil || !strings.Contains(err.Error(), "only the primary device") {
		t.Fatalf("remove on b = %v", err)
	}
	// nothing was sent: a still syncs with its token
	must(t, w.a.Pull())

	c := w.client("c-")
	code, err := w.a.Invite()
	must(t, err)
	_, err = c.Join(w.srv.URL, code, "c")
	must(t, err)
	pending, err := w.b.Pending()
	must(t, err)
	if _, err := w.b.Approve(pending[0].ID); err == nil || !strings.Contains(err.Error(), "only the primary device") {
		t.Fatalf("approve on b = %v", err)
	}
}

// TestPrimaryRefusesForgedChanges checks that the devices of the owner do
// not take a manifest of another device that removes a device, changes
// the primary device or the key, or goes back to format 1
func TestPrimaryRefusesForgedChanges(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(w *world, m *syncproto.Manifest)
		want string
	}{
		{"removal", func(w *world, m *syncproto.Manifest) {
			m.Devices = keepOnly(m.Devices, w.b.st.DeviceID)
			m.Primary = w.b.st.DeviceID
		}, "not by the primary device"},
		{"new primary", func(w *world, m *syncproto.Manifest) { m.Primary = w.b.st.DeviceID }, "not by the primary device"},
		{"new key epoch", func(w *world, m *syncproto.Manifest) { m.Epoch++ }, "not by the primary device"},
		{"format 1", func(w *world, m *syncproto.Manifest) { m.Version, m.Primary = 1, "" }, "format 1 after format 2"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			web, _ := w.pair()
			// a key for the next epoch, so the forged manifest is signed and
			// MAC'd as a real one would be
			key := make([]byte, 32)
			rand.Read(key)
			must(t, vault.SecretSet(w.b.prefix()+"key-"+strconv.Itoa(w.b.st.Epoch+1), key))
			forgePush(t, w.b, func(m *syncproto.Manifest) { c.edit(w, m) })
			err := w.a.Pull()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("a took the forged change: %v", err)
			}
			if _, err := w.a.Store.Find(web.ID); err != nil {
				t.Fatalf("a lost its hosts: %v", err)
			}
		})
	}
}

func keepOnly(ds []syncproto.Device, id string) []syncproto.Device {
	var out []syncproto.Device
	for _, d := range ds {
		if d.ID == id {
			out = append(out, d)
		}
	}
	return out
}

// TestPrimaryOfAnOlderAccount checks the first format 2 manifest of an
// account made before primary devices: it names its own signer
func TestPrimaryOfAnOlderAccount(t *testing.T) {
	devs := []syncproto.Device{{ID: "a"}, {ID: "b"}}
	c := &Client{st: &state{Format: 1, Trusted: devs}}
	m := &syncproto.Manifest{Version: 2, Devices: devs, Primary: "b"}
	if err := c.checkPrimary(&syncproto.Signed{Signer: "b"}, m); err != nil {
		t.Fatalf("own signer as first primary: %v", err)
	}
	if err := c.checkPrimary(&syncproto.Signed{Signer: "a"}, m); err == nil {
		t.Fatal("a device named another one primary")
	}
	m.Primary = "x"
	if err := c.checkPrimary(&syncproto.Signed{Signer: "x"}, m); err == nil {
		t.Fatal("a primary outside the account")
	}
}
