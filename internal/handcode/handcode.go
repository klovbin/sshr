// Package handcode writes bytes as text people copy by hand and type back:
// groups of four Crockford base32 characters, each with a check character,
// so a typo is found and named by its group, a SHA-256 check of the whole
// catches a missing or moved group, the recovery kit of a sync account and
// the recovery code of the vault use it
package handcode

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
)

const (
	// Group is the number of data characters in a group, a check character
	// follows
	Group = 4
	// GroupsPerLine is how many groups a line of the text holds
	GroupsPerLine = 6
	// Crockford base32: no I, L, O, U, read back from what people type
	alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	sumLen   = 4
)

// Encode is raw with a check of the whole, as groups separated by spaces
// and a new line every GroupsPerLine groups
func Encode(raw []byte) string {
	sum := sha256.Sum256(raw)
	chars := base32Encode(append(bytes.Clone(raw), sum[:sumLen]...))
	var out strings.Builder
	for i := 0; i < len(chars); i += Group {
		g := chars[i:min(i+Group, len(chars))]
		n := i / Group
		switch {
		case n == 0:
		case n%GroupsPerLine == 0:
			out.WriteByte('\n')
		default:
			out.WriteByte(' ')
		}
		out.WriteString(g)
		out.WriteByte(groupCheck(g, n))
	}
	return out.String()
}

// Decode reads text as typed back, case, spaces, dashes and the letters
// I, L, O are forgiven, a typo names its group and never its characters,
// they may be part of a secret and the error may end up in a log
func Decode(text string) ([]byte, error) {
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
		if !strings.ContainsRune(alphabet, r) {
			return nil, errors.New("a character that is no part of the code, only digits and the letters A to Z go in")
		}
		clean = append(clean, byte(r))
	}
	var chars []byte
	for i, n := 0, 0; i < len(clean); i, n = i+Group+1, n+1 {
		g := clean[i:min(i+Group+1, len(clean))]
		if len(g) < 2 {
			return nil, fmt.Errorf("group %d is cut short", n+1)
		}
		data := string(g[:len(g)-1])
		if groupCheck(data, n) != g[len(g)-1] {
			return nil, fmt.Errorf("group %d has a typo", n+1)
		}
		chars = append(chars, data...)
	}
	raw, err := base32Decode(string(chars))
	if err != nil || len(raw) <= sumLen {
		return nil, errors.New("too short, a group is missing")
	}
	sum := sha256.Sum256(raw[:len(raw)-sumLen])
	if !bytes.Equal(sum[:sumLen], raw[len(raw)-sumLen:]) {
		return nil, errors.New("the check of the whole fails, a group is missing or out of order")
	}
	return raw[:len(raw)-sumLen], nil
}

// Shaped tells whether text, as Decode reads it, is made only of the
// characters of a code and is at least groups groups long, a code typed
// with a typo is still shaped, a passphrase rarely is
func Shaped(text string, groups int) bool {
	n := 0
	for _, r := range strings.ToUpper(text) {
		switch {
		case r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '-':
		case r == 'I' || r == 'L' || r == 'O' || strings.ContainsRune(alphabet, r):
			n++
		default:
			return false
		}
	}
	return n >= groups*(Group+1)
}

// groupCheck is the check character of group n, weighted so a swap of two
// characters or a group typed in another place is caught too
func groupCheck(g string, n int) byte {
	sum := n*7 + 3
	for i := 0; i < len(g); i++ {
		sum += (i + 2) * strings.IndexByte(alphabet, g[i])
	}
	return alphabet[sum%31]
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
			out.WriteByte(alphabet[(acc>>bits)&31])
		}
	}
	if bits > 0 {
		out.WriteByte(alphabet[(acc<<(5-bits))&31])
	}
	return out.String()
}

func base32Decode(s string) ([]byte, error) {
	var out []byte
	var acc uint
	bits := 0
	for i := 0; i < len(s); i++ {
		v := strings.IndexByte(alphabet, s[i])
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
