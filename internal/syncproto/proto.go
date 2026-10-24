// Package syncproto holds what the sync client and the sync server agree
// on, the server sees only these structures and ciphertext, it cannot read
// hosts or check the MAC, it can only refuse or lose data
package syncproto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// FormatVersion is the version of Manifest, a new optional field keeps
// it, a client reads its own version and older ones and tells the user to
// update on a newer one, format 2 adds Primary and raises it although the
// field is optional: an older client would take a device removal from any
// device and drop the field on its next push, with format 2 it stops and
// asks for an update instead
const FormatVersion = 2

// Limits the server enforces
const (
	MaxBlob     = 1 << 20
	MaxManifest = 8 << 20
	// MaxAccountBlobs and MaxAccountBytes cap what one account stores, a
	// host is one blob of about 512 bytes, unused blobs go after a day
	MaxAccountBlobs = 20000
	MaxAccountBytes = 256 << 20
)

// Device is a device of an account, its ID is derived from its signing key
type Device struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	SignPub []byte `json:"sign_pub"`
	KEMPub  []byte `json:"kem_pub"`
}

// DeviceID is the ID of the device with signing key signPub
func DeviceID(signPub []byte) string {
	sum := sha256.Sum256(signPub)
	return hex.EncodeToString(sum[:16])
}

// Entry is one host in a manifest
type Entry struct {
	// Hash is the SHA-256 of the encrypted blob, empty for a deleted host
	Hash string `json:"hash,omitempty"`
	// Lamport and Device order changes, the higher (Lamport, Device) wins
	Lamport uint64 `json:"lamport"`
	Device  string `json:"device"`
	Deleted bool   `json:"deleted,omitempty"`
}

// Manifest is the state of an account at one point, it is MAC'd with a key
// derived from the vault key and signed by the device that pushed it
type Manifest struct {
	Version int    `json:"version"`
	Account string `json:"account"`
	// Epoch counts vault keys, it goes up when a device is removed
	Epoch int `json:"epoch"`
	// Counter goes up by one with every push
	Counter uint64 `json:"counter"`
	// Prev is the SHA-256 of the body of the manifest this one replaces,
	// a chain a device checks so the server cannot fork the history
	Prev string `json:"prev,omitempty"`
	// Devices are the only devices a client encrypts the vault key to and
	// accepts signatures from, the server cannot add one
	Devices []Device         `json:"devices"`
	Entries map[string]Entry `json:"entries"`
	// Primary is the device that alone may add or remove devices, change
	// the vault key and hand this role on, format 2, set by init, the first
	// format 2 manifest of an older account names the device that wrote it
	Primary string `json:"primary,omitempty"`
}

// Signed is a manifest as stored on the server
type Signed struct {
	// Body is the JSON of the Manifest, kept as bytes so the MAC and the
	// signature cover exactly what was written
	Body   []byte `json:"body"`
	MAC    []byte `json:"mac"`
	Signer string `json:"signer"`
	Sig    []byte `json:"sig"`
}

// BodyHash is the hex SHA-256 of a manifest body, the link in the chain
func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// Envelope is the vault key of one epoch encrypted to one device
type Envelope struct {
	Epoch int    `json:"epoch"`
	Data  []byte `json:"data"`
}

// DeviceRecord is what the server keeps about a device
type DeviceRecord struct {
	Device
	Active bool `json:"active"`
}

// NewAccountRequest creates an account with its first device
type NewAccountRequest struct {
	Device Device `json:"device"`
}

// TokenResponse carries the bearer token of a device, the server keeps
// only its hash
type TokenResponse struct {
	Account string `json:"account"`
	Token   string `json:"token"`
}

// SignInput is what a device signs for a manifest body
func SignInput(body []byte) []byte {
	return append([]byte("sshr-sync manifest\x00"), body...)
}

// SameDevices tells whether two device lists hold the same devices with
// the same keys, a new name alone changes nothing
func SameDevices(a, b []Device) bool {
	if len(a) != len(b) {
		return false
	}
	keys := make(map[string]string, len(a))
	for _, d := range a {
		keys[d.ID] = string(d.SignPub) + "\x00" + string(d.KEMPub)
	}
	for _, d := range b {
		if k, ok := keys[d.ID]; !ok || k != string(d.SignPub)+"\x00"+string(d.KEMPub) {
			return false
		}
	}
	return true
}

// CheckPrimary refuses a manifest m signed by signer that changes who is
// in the account without the primary device of prev, the state before it:
// adding or removing a device, a new vault key epoch or a new primary must
// be signed by the primary of prev, the first format 2 manifest after
// format 1 names its own signer, a format 1 manifest after format 2 is
// refused, prev.Version is the highest format seen, the clients and
// sshr-sync check the same rule
func CheckPrimary(prev, m *Manifest, signer string) error {
	if m.Version < prev.Version {
		return fmt.Errorf("change %d is of format %d after format %d, an older sshr cannot write here, it would drop the primary device", m.Counter, m.Version, prev.Version)
	}
	if m.Version < 2 {
		return nil
	}
	listed := false
	for _, d := range m.Devices {
		listed = listed || d.ID == m.Primary
	}
	if !listed {
		return fmt.Errorf("change %d names a primary device that is not in the account", m.Counter)
	}
	if prev.Primary == "" {
		if m.Primary != signer {
			return fmt.Errorf("change %d makes device %s primary but was written by device %s, the first primary is the device that writes the first change of this format", m.Counter, short(m.Primary), short(signer))
		}
		return nil
	}
	privileged := m.Primary != prev.Primary || m.Epoch > prev.Epoch || !SameDevices(prev.Devices, m.Devices)
	if privileged && signer != prev.Primary {
		return fmt.Errorf("change %d adds or removes a device, changes the vault key or the primary device, but it was written by device %s and not by the primary device %s", m.Counter, short(signer), short(prev.Primary))
	}
	return nil
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}
