package app

import "testing"

// TestEnvSafe checks the host name a local command gets: another sync
// device sets it, it must not stop the command or split it in cmd.exe
// (#290)
func TestEnvSafe(t *testing.T) {
	for _, c := range []struct {
		in      string
		windows bool
		want    string
	}{
		{"web 1", false, "web 1"},
		{"сервер", true, "сервер"},
		{"a\x00b\nc\x7f", false, "abc"},
		{"x & calc", false, "x & calc"},
		{"x & calc | %PATH% ^\"(!)", true, "x _ calc _ _PATH_ _____"},
	} {
		if got := envSafe(c.in, c.windows); got != c.want {
			t.Errorf("envSafe(%q, %v) = %q, want %q", c.in, c.windows, got, c.want)
		}
	}
}
