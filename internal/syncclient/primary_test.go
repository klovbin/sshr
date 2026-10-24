package syncclient

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"sshr.dev/internal/hosts"
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
			if !strings.Contains(err.Error(), "sshr sync leave, then sshr sync init") {
				t.Fatalf("the error names no way out: %v", err)
			}
			// the way out: a new account from the hosts here
			must(t, w.a.Leave(false))
			must(t, w.a.Init(w.srv.URL, "laptop"))
			if _, err := w.a.Store.Find(web.ID); err != nil || w.a.st.Primary != w.a.st.DeviceID {
				t.Fatalf("new account: %v, primary %q", err, w.a.st.Primary)
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

// TestPrimaryRefusesRepeatedDevice checks that a device list repeating an
// ID does not slip past the rule: [a, b, c] to [a, b, b] removes c (#295)
func TestPrimaryRefusesRepeatedDevice(t *testing.T) {
	w := newWorld(t)
	w.pair()
	c := w.client("c-")
	w.join(c)
	must(t, w.b.Pull())
	n, b := forgeManifest(t, w.b, func(m *syncproto.Manifest) {
		m.Devices = append(keepOnly(m.Devices, w.a.st.DeviceID), keepOnly(m.Devices, w.b.st.DeviceID)[0], keepOnly(m.Devices, w.b.st.DeviceID)[0])
	})
	if err := w.b.backend().PutManifest(n-1, b); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("the server took the list: %v", err)
	}
	must(t, os.WriteFile(filepath.Join(w.manifestDir(), strconv.FormatUint(n, 10)+".json"), b, 0o600))
	if err := w.a.Pull(); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("a took the list: %v", err)
	}
}

// TestPrimaryAfterAFailedPull checks that a pull whose apply fails does
// not keep the primary of the manifests it did not apply: the device would
// refuse them on the next pull and stay stuck (#296)
func TestPrimaryAfterAFailedPull(t *testing.T) {
	w := newWorld(t)
	web, _ := w.pair()
	c := w.client("c-")
	code, err := w.a.Invite()
	must(t, err)
	_, err = c.Join(w.srv.URL, code, "c")
	must(t, err)
	pending, err := w.a.Pending()
	must(t, err)
	// one manifest of a adds c and changes web, the next hands the role to b
	editHost(t, w.a, web.ID, func(h *hosts.Host) { h.Port, h.Password = 2201, "" })
	_, err = w.a.Approve(pending[0].ID)
	must(t, err)
	_, err = w.a.HandPrimary(w.b.st.DeviceID[:8], func(string, string) bool { return true })
	must(t, err)
	blob := filepath.Join(filepath.Dir(w.manifestDir()), "blobs", w.a.st.Entries[web.ID].Blob)
	saved, err := os.ReadFile(blob)
	must(t, err)
	must(t, os.Remove(blob))
	if err := w.b.Pull(); err == nil {
		t.Fatal("the pull did not fail without the blob")
	}
	must(t, os.WriteFile(blob, saved, 0o600))
	must(t, w.b.Pull())
	if w.b.st.Primary != w.b.st.DeviceID {
		t.Fatalf("primary on b %q", w.b.st.Primary)
	}
}

// TestServerRefusesBrokenManifests checks that sshr-sync does not store a
// manifest every client would refuse, as head it would stop the account
// (#298)
func TestServerRefusesBrokenManifests(t *testing.T) {
	for name, edit := range map[string]func(*syncproto.Manifest){
		"wrong prev":   func(m *syncproto.Manifest) { m.Prev = strings.Repeat("0", 64) },
		"older epoch":  func(m *syncproto.Manifest) { m.Epoch-- },
		"newer format": func(m *syncproto.Manifest) { m.Version = 99 },
		"wrong id":     func(m *syncproto.Manifest) { m.Devices[1].Name, m.Devices[1].ID = "x", strings.Repeat("a", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			w.pair()
			// any key will do for the MAC, the server cannot check it
			key := make([]byte, 32)
			rand.Read(key)
			must(t, vault.SecretSet(w.b.prefix()+"key-"+strconv.Itoa(w.b.st.Epoch-1), key))
			n, b := forgeManifest(t, w.b, edit)
			if err := w.b.backend().PutManifest(n-1, b); err == nil || !strings.Contains(err.Error(), "403") {
				t.Fatalf("the server took it: %v", err)
			}
			must(t, w.a.Pull())
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
	// the first primary must not remove a device or change the key in the
	// same change (#297)
	m = &syncproto.Manifest{Version: 2, Devices: devs[1:], Primary: "b"}
	if err := c.checkPrimary(&syncproto.Signed{Signer: "b"}, m); err == nil {
		t.Fatal("the first primary removed a device in the same step")
	}
	m = &syncproto.Manifest{Version: 2, Devices: devs, Primary: "b", Epoch: 1}
	if err := c.checkPrimary(&syncproto.Signed{Signer: "b"}, m); err == nil {
		t.Fatal("the first primary changed the key in the same step")
	}
}
