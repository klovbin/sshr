package syncclient

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"sshr.dev/internal/syncproto"
	"sshr.dev/internal/vault"
)

// forgeManifest is the next manifest as device c would sign it, with edit
// applied to a copy of the head, the way a stolen device with a changed
// sshr could, it skips every check of the client
func forgeManifest(t *testing.T, c *Client, edit func(*syncproto.Manifest)) (uint64, []byte) {
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
	return m.Counter, b
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
	// a changed sshr on b goes to sshr-sync directly, the server refuses
	// to revoke the token of a and to activate c
	if err := w.b.backend().RemoveDevice(w.a.st.DeviceID); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("the server let b revoke a: %v", err)
	}
	if err := w.b.backend().Activate(pending[0].ID); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("the server let b activate c: %v", err)
	}
	must(t, w.a.Pull())
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
			n, b := forgeManifest(t, w.b, func(m *syncproto.Manifest) { c.edit(w, m) })
			// sshr-sync refuses it itself
			if err := w.b.backend().PutManifest(n-1, b); err == nil || !strings.Contains(err.Error(), "403") {
				t.Fatalf("the server took the forged change: %v", err)
			}
			// a server that does not check, or an object store, keeps it,
			// the owner's devices must refuse it on their own
			must(t, os.WriteFile(filepath.Join(w.manifestDir(), strconv.FormatUint(n, 10)+".json"), b, 0o600))
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

// TestHandPrimary checks that the primary device hands its role on, the
// new primary then removes devices, the old one no longer can, and no
// other device can hand it on
func TestHandPrimary(t *testing.T) {
	w := newWorld(t)
	w.pair()
	yes := func(string, string) bool { return true }
	if _, err := w.b.HandPrimary(w.a.st.DeviceID[:8], yes); err == nil || !strings.Contains(err.Error(), "only the primary device") {
		t.Fatalf("b took the role: %v", err)
	}
	if _, err := w.a.HandPrimary(w.b.st.DeviceID[:8], func(string, string) bool { return false }); err == nil {
		t.Fatal("handed on without a yes")
	}
	if w.a.st.Primary != w.a.st.DeviceID {
		t.Fatal("a refused hand-over changed the primary")
	}
	d, err := w.a.HandPrimary(w.b.st.DeviceID[:8], yes)
	must(t, err)
	if d.ID != w.b.st.DeviceID || w.a.st.Primary != w.b.st.DeviceID {
		t.Fatalf("primary on a after the hand-over: %q", w.a.st.Primary)
	}
	must(t, w.b.Pull())
	if w.b.st.Primary != w.b.st.DeviceID {
		t.Fatalf("b does not see itself as primary: %q", w.b.st.Primary)
	}
	if _, err := w.a.RemoveDevice(w.b.st.DeviceID[:8]); err == nil || !strings.Contains(err.Error(), "only the primary device") {
		t.Fatalf("the old primary removed a device: %v", err)
	}
	_, err = w.b.RemoveDevice(w.a.st.DeviceID[:8])
	must(t, err)
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
