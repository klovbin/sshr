package syncclient

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
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
	kitGroup         = 4 // data characters in a group, a check character follows
	kitGroupsPerLine = 6
	// Crockford base32: no I, L, O, U, read back from what people type
	kitAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
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

// encodeKit is the secret part of a kit as text people copy by hand:
// groups of four Crockford base32 characters, each with a check character,
// so a typo is found and named, a SHA-256 check of the whole catches the
// rest, pass wraps it with Argon2id when not empty
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
	sum := sha256.Sum256(raw)
	raw = append(raw, sum[:4]...)

	chars := base32Encode(raw)
	var out strings.Builder
	for i := 0; i < len(chars); i += kitGroup {
		g := chars[i:min(i+kitGroup, len(chars))]
		n := i / kitGroup
		switch {
		case n == 0:
		case n%kitGroupsPerLine == 0:
			out.WriteByte('\n')
		default:
			out.WriteByte(' ')
		}
		out.WriteString(g)
		out.WriteByte(groupCheck(g, n))
	}
	return out.String(), nil
}

// decodeKit reads a kit as typed back, case, spaces, dashes and the
// letters I, L, O are forgiven, pass is asked only for a kit made with a
// passphrase
func decodeKit(text string, pass func() (string, error)) (recoveryKit, error) {
	var clean []byte
	for _, r := range strings.ToUpper(text) {
		switch r {
		case ' ', '\t', '\n', '\r', '-':
			continue
		case 'I', 'L':
			r = '1'
		case 'O':
			r = '0'
		}
		if !strings.ContainsRune(kitAlphabet, r) {
			// the character itself is not named, it may be part of the
			// secret and the error may end up in a log or a report
			return recoveryKit{}, errors.New("recovery kit: a character that is no part of a kit, only digits and the letters A to Z go in")
		}
		clean = append(clean, byte(r))
	}
	var chars []byte
	for i, n := 0, 0; i < len(clean); i, n = i+kitGroup+1, n+1 {
		g := clean[i:min(i+kitGroup+1, len(clean))]
		if len(g) < 2 {
			return recoveryKit{}, fmt.Errorf("recovery kit: group %d is cut short", n+1)
		}
		data := string(g[:len(g)-1])
		if groupCheck(data, n) != g[len(g)-1] {
			return recoveryKit{}, fmt.Errorf("recovery kit: group %d has a typo", n+1)
		}
		chars = append(chars, data...)
	}
	raw, err := base32Decode(string(chars))
	if err != nil || len(raw) < 2+4 {
		return recoveryKit{}, errors.New("recovery kit: too short, a group is missing")
	}
	sum := sha256.Sum256(raw[:len(raw)-4])
	if !bytes.Equal(sum[:4], raw[len(raw)-4:]) {
		return recoveryKit{}, errors.New("recovery kit: the check of the whole kit fails, a group is missing or out of order")
	}
	raw = raw[:len(raw)-4]
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

// groupCheck is the check character of group n, weighted so a swap of two
// characters or a group typed in another place is caught too
func groupCheck(g string, n int) byte {
	sum := n*7 + 3
	for i := 0; i < len(g); i++ {
		sum += (i + 2) * strings.IndexByte(kitAlphabet, g[i])
	}
	return kitAlphabet[sum%31]
}

func base32Encode(b []byte) string {
	var out strings.Builder
	var acc uint
	bits := 0
	for _, c := range b {
		acc = acc<<8 | uint(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out.WriteByte(kitAlphabet[(acc>>bits)&31])
		}
	}
	if bits > 0 {
		out.WriteByte(kitAlphabet[(acc<<(5-bits))&31])
	}
	return out.String()
}

func base32Decode(s string) ([]byte, error) {
	var out []byte
	var acc uint
	bits := 0
	for i := 0; i < len(s); i++ {
		v := strings.IndexByte(kitAlphabet, s[i])
		if v < 0 {
			return nil, errors.New("bad character")
		}
		acc = acc<<5 | uint(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
		}
	}
	return out, nil
}
