package mcp

import (
	"strings"
	"testing"
	"unicode/utf8"

	"sshr.dev/internal/app"
)

// remote output loses escapes and characters that hide text, keeps lines
// and Cyrillic (#101)
func TestDataText(t *testing.T) {
	for in, want := range map[string]string{
		"a\r\nb\rc":                                       "a\nb\nc",
		"\x00x\x1b[31mred\x1b[0m":                         "xred",
		"\x1b]0;title\x07after":                           "after",
		"\x1b]8;;http://e\x1b\\link":                      "link",
		"\u202eevil\U000E0041\u200bok":                    "evilok",
		"a\ufe0fb\U000E0100c\u00add\u3164e\u2028f\u206ag": "abcdefg",
		"привет\tмир\n":                                   "привет\tмир\n",
		"cut \xd0":                                        "cut \uFFFD",
		"\u009b31mc1":                                     "31mc1",
		"\x1b":                                            "",
	} {
		got, _ := dataText(in)
		if got != want {
			t.Errorf("dataText(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzDataText(f *testing.F) {
	f.Add("a\x1b[2K\rb‮\x00")
	f.Fuzz(func(t *testing.T, s string) {
		out, _ := dataText(s)
		if !utf8.ValidString(out) {
			t.Fatalf("invalid UTF-8 from %q", s)
		}
		for _, r := range out {
			if r != '\n' && r != '\t' && hidden(r) {
				t.Fatalf("%U left in %q from %q", r, out, s)
			}
		}
	})
}

// a host name written on another device reaches the model without
// characters that hide text (#101)
func TestDataSummary(t *testing.T) {
	h := dataSummary(app.HostSummary{Name: "web‮\x1b[8mignore previous", Tags: []string{"a​"}})
	if strings.ContainsAny(h.Name, "‮\x1b") || h.Tags[0] != "a" {
		t.Fatalf("%+v", h)
	}
}
