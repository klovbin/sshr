package syncclient

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"sshr.dev/internal/handcode"
)

// recoveryKit is the secret part of a printed recovery kit (#150): the
// seed of the recovery device, its sshr-sync token (empty on an object
// store, its credential is asked on restore) and the change counter when
// the kit was printed, a server that serves an older head is refused
type recoveryKit struct {
	Seed  []byte
	Token string
	Floor uint64
}

const (
	kitVersion       = 1
	kitFlagPassword  = 1
	kitGroupsPerLine = handcode.GroupsPerLine
)

// the same Argon2id cost as the passphrase vault, a kit is attacked
// offline once someone has the paper
var kitArgon = struct {
	Time, MemoryKiB uint32
	Threads         uint8
}{3, 64 * 1024, 4}

var kitAAD = []byte("sshr/recovery-kit/v1")

// errKitPassphrase is a wrong passphrase for a kit
var errKitPassphrase = errors.New("the passphrase of the recovery kit is wrong")

// encodeKit is the secret part of a kit as text people copy by hand, see
// handcode, pass wraps it with Argon2id when not empty
func encodeKit(k recoveryKit, pass string) (string, error) {
	if len(k.Seed) != 32 || len(k.Token) > 255 {
		return "", errors.New("recovery kit: bad seed or token")
	}
	var body bytes.Buffer
	body.Write(k.Seed)
	body.WriteByte(byte(len(k.Token)))
	body.WriteString(k.Token)
	binary.Write(&body, binary.BigEndian, k.Floor)

	raw := []byte{kitVersion, 0}
	if pass == "" {
		raw = append(raw, body.Bytes()...)
	} else {
		raw[1] = kitFlagPassword
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return "", err
		}
		aead, err := chacha20poly1305.NewX(argon2.IDKey([]byte(pass), salt, kitArgon.Time, kitArgon.MemoryKiB, kitArgon.Threads, chacha20poly1305.KeySize))
		if err != nil {
			return "", err
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return "", err
		}
		raw = append(raw, salt...)
		raw = append(raw, aead.Seal(nonce, nonce, body.Bytes(), kitAAD)...)
	}
	return handcode.Encode(raw), nil
}

// decodeKit reads a kit as typed back, case, spaces, dashes and the
// letters I, L, O are forgiven, pass is asked only for a kit made with a
// passphrase
func decodeKit(text string, pass func() (string, error)) (recoveryKit, error) {
	raw, err := handcode.Decode(text)
	if err != nil {
		return recoveryKit{}, fmt.Errorf("recovery kit: %w", err)
	}
	if len(raw) < 2 {
		return recoveryKit{}, errors.New("recovery kit: too short, a group is missing")
	}
	if raw[0] != kitVersion {
		return recoveryKit{}, fmt.Errorf("recovery kit of version %d, this sshr reads version %d, update sshr", raw[0], kitVersion)
	}
	body := raw[2:]
	if raw[1]&kitFlagPassword != 0 {
		p, err := pass()
		if err != nil {
			return recoveryKit{}, err
		}
		if len(body) < 16+chacha20poly1305.NonceSizeX {
			return recoveryKit{}, errors.New("recovery kit: damaged")
		}
		salt, sealed := body[:16], body[16:]
		aead, err := chacha20poly1305.NewX(argon2.IDKey([]byte(p), salt, kitArgon.Time, kitArgon.MemoryKiB, kitArgon.Threads, chacha20poly1305.KeySize))
		if err != nil {
			return recoveryKit{}, err
		}
		if body, err = aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], kitAAD); err != nil {
			return recoveryKit{}, errKitPassphrase
		}
	}
	if len(body) < 32+1 || len(body) != 32+1+int(body[32])+8 {
		return recoveryKit{}, errors.New("recovery kit: damaged")
	}
	n := int(body[32])
	return recoveryKit{
		Seed:  append([]byte(nil), body[:32]...),
		Token: string(body[33 : 33+n]),
		Floor: binary.BigEndian.Uint64(body[33+n:]),
	}, nil
}
