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
	// Recovery is the device of a printed recovery kit (#150), it may only
	// claim the account and, RecoveryWait seconds later, hand it to one new
	// device, the primary sets both, Claim is the counter of the manifest
	// with which the kit device claimed the account, 0 for none
	Recovery     string `json:"recovery,omitempty"`
	RecoveryWait int64  `json:"recovery_wait,omitempty"`
	Claim        uint64 `json:"claim,omitempty"`
}

// MinRecoveryWait is the shortest wait between a claim of the recovery kit
// and the hand-over, the owner's devices must have a day to cancel
const MinRecoveryWait = 24 * 60 * 60

// Step is what a manifest does as CheckPrimary sees it
type Step int

const (
	// StepNormal is any change the rules allow its signer
	StepNormal Step = iota
	// StepClaim is the recovery kit device claiming the account
	StepClaim
	// StepRecover is the recovery kit device handing the account to a new
	// device, the caller checks that the wait since the claim is over
	StepRecover
)

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
// the same keys, a new name alone changes nothing, a list that repeats an
// ID is never the same as another one
func SameDevices(a, b []Device) bool {
	if len(a) != len(b) || RepeatedDevice(a) != "" || RepeatedDevice(b) != "" {
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

// RepeatedDevice is an ID listed twice in ds, empty when there is none
func RepeatedDevice(ds []Device) string {
	seen := make(map[string]bool, len(ds))
	for _, d := range ds {
		if seen[d.ID] {
			return d.ID
		}
		seen[d.ID] = true
	}
	return ""
}

// CheckPrimary refuses a manifest m signed by signer that changes who is
// in the account without the primary device of prev, the state before it:
// adding or removing a device, a new vault key epoch, a new primary or a
// change of the recovery kit must be signed by the primary of prev, the
// first format 2 manifest after format 1 names its own signer and changes
// nothing else, a format 1 manifest after format 2 is refused, the device
// of the recovery kit may only claim or hand over, prev.Version is the
// highest format seen, the clients and sshr-sync check the same rule
func CheckPrimary(prev, m *Manifest, signer string) (Step, error) {
	if m.Version < prev.Version {
		return 0, fmt.Errorf("change %d is of format %d after format %d, an older sshr cannot write here, it would drop the primary device", m.Counter, m.Version, prev.Version)
	}
	if m.Version < 2 {
		return StepNormal, nil
	}
	if id := RepeatedDevice(m.Devices); id != "" {
		return 0, fmt.Errorf("change %d lists device %s twice", m.Counter, short(id))
	}
	if !listed(m.Devices, m.Primary) {
		return 0, fmt.Errorf("change %d names a primary device that is not in the account", m.Counter)
	}
	if m.Recovery != "" && (!listed(m.Devices, m.Recovery) || m.Recovery == m.Primary || m.RecoveryWait < MinRecoveryWait) {
		return 0, fmt.Errorf("change %d names a recovery kit device that is not in the account, is the primary, or waits less than a day", m.Counter)
	}
	if prev.Primary == "" {
		if m.Primary != signer {
			return 0, fmt.Errorf("change %d makes device %s primary but was written by device %s, the first primary is the device that writes the first change of this format", m.Counter, short(m.Primary), short(signer))
		}
		// naming the first primary is all it may do, a device that pushes
		// first must not also throw the others out in the same step
		if m.Epoch != prev.Epoch || !SameDevices(prev.Devices, m.Devices) || m.Recovery != "" || m.Claim != 0 {
			return 0, fmt.Errorf("change %d names the first primary device and changes the devices or the vault key in the same step", m.Counter)
		}
		return StepNormal, nil
	}
	if signer == prev.Primary {
		return StepNormal, nil
	}
	if prev.Recovery != "" && signer == prev.Recovery {
		return recoveryStep(prev, m)
	}
	if m.Primary != prev.Primary || m.Epoch > prev.Epoch || !SameDevices(prev.Devices, m.Devices) ||
		m.Recovery != prev.Recovery || m.RecoveryWait != prev.RecoveryWait || m.Claim != prev.Claim {
		return 0, fmt.Errorf("change %d adds or removes a device, changes the vault key, the primary device or the recovery kit, but it was written by device %s and not by the primary device %s", m.Counter, short(signer), short(prev.Primary))
	}
	return StepNormal, nil
}

// recoveryStep is what the recovery kit device may write: a claim that
// changes nothing else, or once claimed the hand-over to exactly one new
// device that becomes primary, the hosts, the key and the kit stay, a
// kit that wrote anything else could take the account at once
func recoveryStep(prev, m *Manifest) (Step, error) {
	same := m.Epoch == prev.Epoch && m.Recovery == prev.Recovery && m.RecoveryWait == prev.RecoveryWait && SameEntries(prev.Entries, m.Entries)
	if same && prev.Claim == 0 && m.Claim == m.Counter && m.Primary == prev.Primary && SameDevices(prev.Devices, m.Devices) {
		return StepClaim, nil
	}
	if same && prev.Claim != 0 && m.Claim == 0 && len(m.Devices) == len(prev.Devices)+1 && !listed(prev.Devices, m.Primary) {
		var rest []Device
		for _, d := range m.Devices {
			if d.ID != m.Primary {
				rest = append(rest, d)
			}
		}
		if SameDevices(prev.Devices, rest) {
			return StepRecover, nil
		}
	}
	return 0, fmt.Errorf("change %d was written by the recovery kit device, it may only claim the account or, after the wait, hand it to one new device", m.Counter)
}

// SameEntries tells whether two manifests list the same hosts
func SameEntries(a, b map[string]Entry) bool {
	if len(a) != len(b) {
		return false
	}
	for id, e := range a {
		if f, ok := b[id]; !ok || f != e {
			return false
		}
	}
	return true
}

func listed(ds []Device, id string) bool {
	for _, d := range ds {
		if d.ID == id {
			return true
		}
	}
	return false
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}
