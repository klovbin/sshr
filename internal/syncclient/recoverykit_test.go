package syncclient

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func testKit() recoveryKit {
	seed := bytes.Repeat([]byte{7}, 32)
	seed[0] = 1
	return recoveryKit{Seed: seed, Token: "tok-0123456789abcdef", Floor: 4242}
}

func noPass() (string, error) { return "", errors.New("asked for a passphrase") }

// TestRecoveryKitRoundTrip checks that a kit reads back as printed, also
// typed in lower case with I, L and O for 1, 1 and 0 (#150)
func TestRecoveryKitRoundTrip(t *testing.T) {
	text, err := encodeKit(testKit(), "")
	must(t, err)
	got, err := decodeKit(text, noPass)
	must(t, err)
	if !bytes.Equal(got.Seed, testKit().Seed) || got.Token != testKit().Token || got.Floor != 4242 {
		t.Fatalf("read back %+v", got)
	}
	typed := strings.NewReplacer("1", "l", "0", "o").Replace(strings.ToLower(text))
	if _, err := decodeKit(typed, noPass); err != nil {
		t.Fatalf("typed by hand: %v", err)
	}
	for _, line := range strings.Split(text, "\n") {
		if len(strings.Fields(line)) > kitGroupsPerLine {
			t.Fatalf("line too long: %q", line)
		}
	}
}

// TestRecoveryKitPassphrase checks the kit under a passphrase: the right
// one opens it, a wrong one says so, none is asked for a kit without one
func TestRecoveryKitPassphrase(t *testing.T) {
	text, err := encodeKit(testKit(), "correct horse")
	must(t, err)
	got, err := decodeKit(text, func() (string, error) { return "correct horse", nil })
	must(t, err)
	if got.Token != testKit().Token {
		t.Fatalf("read back %+v", got)
	}
	if _, err := decodeKit(text, func() (string, error) { return "wrong", nil }); !errors.Is(err, errKitPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
}

// TestRecoveryKitTypos checks that a changed character names its group,
// two swapped characters are caught, and a missing group is caught by the
// check of the whole kit
func TestRecoveryKitTypos(t *testing.T) {
	text, err := encodeKit(testKit(), "")
	must(t, err)
	groups := strings.Fields(text)
	bad := append([]string(nil), groups...)
	g := []byte(bad[3])
	if g[1] == 'A' {
		g[1] = 'B'
	} else {
		g[1] = 'A'
	}
	bad[3] = string(g)
	if _, err := decodeKit(strings.Join(bad, " "), noPass); err == nil || !strings.Contains(err.Error(), "group 4") || strings.Contains(err.Error(), bad[3]) {
		t.Fatalf("a typo in group 4, named without its characters (#307): %v", err)
	}
	swapped := append([]string(nil), groups...)
	s := []byte(swapped[2])
	if s[0] != s[1] {
		s[0], s[1] = s[1], s[0]
		swapped[2] = string(s)
		if _, err := decodeKit(strings.Join(swapped, " "), noPass); err == nil {
			t.Fatal("two swapped characters went through")
		}
	}
	missing := append(append([]string(nil), groups[:5]...), groups[6:]...)
	if _, err := decodeKit(strings.Join(missing, " "), noPass); err == nil {
		t.Fatal("a missing group went through")
	}
}
