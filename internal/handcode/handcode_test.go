package handcode

import (
	"bytes"
	"strings"
	"testing"
)

// what Encode writes comes back from Decode as typed by a person: lower
// case, dashes, O for 0, a typo names its group, a group left out fails
// the check of the whole
func TestRoundTripAndTypos(t *testing.T) {
	raw := []byte("0123456789abcdef")
	text := Encode(raw)
	typed := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(text, " ", "-"), "0", "O"))
	got, err := Decode(typed)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("Decode(%q) = %x, %v", typed, got, err)
	}
	groups := strings.Fields(text)
	bad := []byte(groups[2])
	if bad[0] == 'A' {
		bad[0] = 'B'
	} else {
		bad[0] = 'A'
	}
	groups[2] = string(bad)
	if _, err := Decode(strings.Join(groups, " ")); err == nil || !strings.Contains(err.Error(), "group 3") {
		t.Errorf("a typo in group 3: %v", err)
	}
	all := strings.Fields(text)
	if _, err := Decode(strings.Join(append(all[:1:1], all[2:]...), " ")); err == nil {
		t.Error("a missing group went through")
	}
	if _, err := Decode("!"); err == nil {
		t.Error("a character outside the code went through")
	}
}
