// Package syncclient syncs the hosts of this machine through an sshr-sync
// server, end to end encrypted, the server gets only ciphertext and
// manifests it cannot forge, private keys stored in sshr never leave the
// machine
package syncclient

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"

	"sshr.dev/internal/syncproto"
)

// kem is ML-KEM-768 with X25519 (X-Wing), the vault key lives for years,
// a recorded envelope must stay closed against a future quantum computer
func kem() hpke.KEM { return hpke.MLKEM768X25519() }

// deviceKeys are the keys of this device, all derived from one 32-byte
// seed kept in the system keychain
type deviceKeys struct {
	sign ed25519.PrivateKey
	kem  hpke.PrivateKey
}

func derive(seed []byte, label string, n int) []byte {
	out, err := hkdf.Key(sha256.New, seed, nil, "sshr-sync device "+label, n)
	if err != nil {
		panic(err)
	}
	return out
}

func newDeviceKeys(seed []byte) (*deviceKeys, error) {
	if len(seed) != 32 {
		return nil, errors.New("device seed must be 32 bytes")
	}
	k, err := kem().DeriveKeyPair(derive(seed, "kem", 64))
	if err != nil {
		return nil, err
	}
	return &deviceKeys{sign: ed25519.NewKeyFromSeed(derive(seed, "ed25519", 32)), kem: k}, nil
}

func (k *deviceKeys) device(name string) syncproto.Device {
	pub := k.sign.Public().(ed25519.PublicKey)
	return syncproto.Device{ID: syncproto.DeviceID(pub), Name: name, SignPub: pub, KEMPub: k.kem.PublicKey().Bytes()}
}

// Fingerprint is what a person compares between two screens, 20 hex
// characters of the hash of a device's signing key in groups of four
// DeviceFingerprint is what people compare when a device joins or the
// primary role moves, it covers the signing key and the encryption key
// the vault key is sealed to, a server that swaps either changes it
func DeviceFingerprint(d syncproto.Device) string {
	return Fingerprint(append(append(append([]byte(nil), d.SignPub...), 0), d.KEMPub...))
}

func Fingerprint(signPub []byte) string {
	sum := sha256.Sum256(append([]byte("sshr-sync fingerprint\x00"), signPub...))
	h := hex.EncodeToString(sum[:10])
	var parts []string
	for i := 0; i < len(h); i += 4 {
		parts = append(parts, h[i:i+4])
	}
	return strings.Join(parts, "-")
}

func envelopeInfo(account string, epoch int) []byte {
	return []byte(fmt.Sprintf("sshr-vault-key\x00%s\x00%d", account, epoch))
}

// sealEnvelope encrypts the vault key of epoch to one device
func sealEnvelope(d syncproto.Device, account string, epoch int, vaultKey []byte) (syncproto.Envelope, error) {
	pub, err := kem().NewPublicKey(d.KEMPub)
	if err != nil {
		return syncproto.Envelope{}, fmt.Errorf("device %s has a bad key: %v", d.ID, err)
	}
	data, err := hpke.Seal(pub, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), envelopeInfo(account, epoch), vaultKey)
	return syncproto.Envelope{Epoch: epoch, Data: data}, err
}

func (k *deviceKeys) openEnvelope(env syncproto.Envelope, account string) ([]byte, error) {
	key, err := hpke.Open(k.kem, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), envelopeInfo(account, env.Epoch), env.Data)
	if err != nil || len(key) != 32 {
		return nil, errors.New("the vault key envelope for this device does not open")
	}
	return key, nil
}

func vaultSubkey(vaultKey []byte, label string) []byte {
	out, err := hkdf.Key(sha256.New, vaultKey, nil, "sshr-sync "+label, 32)
	if err != nil {
		panic(err)
	}
	return out
}

func entryAAD(account, entryID string, epoch int) []byte {
	return []byte(fmt.Sprintf("sshr-sync\x00v1\x00%s\x00%s\x00%d", account, entryID, epoch))
}

// padBucket hides the exact size of a host, a host with forwards would
// otherwise stand out by its length
const padBucket = 512

// sealEntry encrypts one host, the plaintext is padded to padBucket
func sealEntry(vaultKey []byte, account, entryID string, epoch int, plain []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(vaultSubkey(vaultKey, "entries"))
	if err != nil {
		return nil, err
	}
	size := 4 + len(plain)
	size += (padBucket - size%padBucket) % padBucket
	padded := make([]byte, size)
	binary.BigEndian.PutUint32(padded, uint32(len(plain)))
	copy(padded[4:], plain)
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+size+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, padded, entryAAD(account, entryID, epoch)), nil
}

func openEntry(vaultKey []byte, account, entryID string, epoch int, blob []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(vaultSubkey(vaultKey, "entries"))
	if err != nil {
		return nil, err
	}
	if len(blob) < aead.NonceSize()+aead.Overhead()+4 {
		return nil, errors.New("entry too short")
	}
	padded, err := aead.Open(nil, blob[:aead.NonceSize()], blob[aead.NonceSize():], entryAAD(account, entryID, epoch))
	if err != nil {
		return nil, fmt.Errorf("entry %s does not open with the vault key", entryID)
	}
	n := binary.BigEndian.Uint32(padded)
	if int(n) > len(padded)-4 {
		return nil, fmt.Errorf("entry %s is damaged", entryID)
	}
	return padded[4 : 4+n], nil
}

func manifestMAC(vaultKey, body []byte) []byte {
	m := hmac.New(sha256.New, vaultSubkey(vaultKey, "manifest"))
	m.Write(body)
	return m.Sum(nil)
}

func signInput(body []byte) []byte { return syncproto.SignInput(body) }

// signManifest makes the stored form of m, MAC'd with the vault key of its
// epoch and signed by this device
func (k *deviceKeys) signManifest(m *syncproto.Manifest, vaultKey []byte, deviceID string) ([]byte, *syncproto.Signed, error) {
	body, err := jsonMarshal(m)
	if err != nil {
		return nil, nil, err
	}
	sm := &syncproto.Signed{Body: body, MAC: manifestMAC(vaultKey, body), Signer: deviceID, Sig: ed25519.Sign(k.sign, signInput(body))}
	b, err := jsonMarshal(sm)
	return b, sm, err
}

// verifySignature checks that sm is signed by a device of trusted
func verifySignature(sm *syncproto.Signed, trusted []syncproto.Device) error {
	for _, d := range trusted {
		if d.ID == sm.Signer {
			if len(d.SignPub) != ed25519.PublicKeySize || !ed25519.Verify(d.SignPub, signInput(sm.Body), sm.Sig) {
				return fmt.Errorf("manifest signature of device %s does not verify", sm.Signer)
			}
			return nil
		}
	}
	return fmt.Errorf("manifest signed by device %s, which this device does not trust", sm.Signer)
}

func verifyMAC(sm *syncproto.Signed, vaultKey []byte) error {
	if !hmac.Equal(sm.MAC, manifestMAC(vaultKey, sm.Body)) {
		return errors.New("manifest MAC does not verify with the vault key")
	}
	return nil
}

func blobHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
