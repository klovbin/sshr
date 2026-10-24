// Package ext holds what sshr knows about extensions: executables the user
// installed into ~/.sshr/extensions/<name>/ that sshr runs for a command it
// does not have itself, see docs/ARCHITECTURE.md
package ext

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode"
)

// Protocol is the version of what sshr and an extension say to each other,
// an extension declares the one it was written for and sshr refuses another
const Protocol = 1

// Kinds an extension can have
const (
	// KindCommand runs as `sshr <name> args...` with the terminal of the user
	KindCommand = "command"
	// KindImport prints hosts as JSON that sshr takes in
	KindImport = "import"
)

// ManifestFile is the file every extension carries in its folder
const ManifestFile = "sshr-ext.json"

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// Manifest is sshr-ext.json, written by the author of the extension
type Manifest struct {
	Protocol    int    `json:"protocol"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	// Command is the argument list to run, per OS name as GOOS spells it
	// (linux, darwin, windows), "default" is used for any other, no shell
	// is involved, the first argument is a file of the extension's folder
	Command map[string][]string `json:"command"`
	Kinds   []string            `json:"kinds"`
}

// ParseManifest reads and checks a manifest, nothing in it is run
func ParseManifest(data []byte) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("%s: %v", ManifestFile, err)
	}
	if m.Protocol != Protocol {
		return Manifest{}, fmt.Errorf("%s: protocol %d, this sshr speaks %d", ManifestFile, m.Protocol, Protocol)
	}
	if err := CheckName(m.Name); err != nil {
		return Manifest{}, fmt.Errorf("%s: %v", ManifestFile, err)
	}
	if m.Version == "" || len(m.Version) > 40 {
		return Manifest{}, fmt.Errorf("%s: version is empty or longer than 40 characters", ManifestFile)
	}
	if len(m.Description) > 200 {
		return Manifest{}, fmt.Errorf("%s: description is longer than 200 characters", ManifestFile)
	}
	// the install screen prints these before the yes, a control character
	// could rewrite the lines the user reads
	if err := printable("version", m.Version); err != nil {
		return Manifest{}, fmt.Errorf("%s: %v", ManifestFile, err)
	}
	if err := printable("description", m.Description); err != nil {
		return Manifest{}, fmt.Errorf("%s: %v", ManifestFile, err)
	}
	if len(m.Kinds) == 0 {
		return Manifest{}, fmt.Errorf("%s: kinds is empty, use %q or %q", ManifestFile, KindCommand, KindImport)
	}
	for _, k := range m.Kinds {
		if k != KindCommand && k != KindImport {
			return Manifest{}, fmt.Errorf("%s: unknown kind %q", ManifestFile, k)
		}
	}
	if len(m.Command) == 0 {
		return Manifest{}, fmt.Errorf("%s: command is empty", ManifestFile)
	}
	for goos, argv := range m.Command {
		if err := checkArgv(argv); err != nil {
			return Manifest{}, fmt.Errorf("%s: command for %q: %v", ManifestFile, goos, err)
		}
		for _, a := range argv {
			if err := printable("a command argument", a); err != nil {
				return Manifest{}, fmt.Errorf("%s: command for %q: %v", ManifestFile, goos, err)
			}
		}
	}
	return m, nil
}

// printable refuses control, line separator and bidi characters in a field
// the install screen shows
func printable(what, s string) error {
	for _, r := range s {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || unicode.In(r, unicode.Bidi_Control) {
			return fmt.Errorf("%s holds the control character %U", what, r)
		}
	}
	return nil
}

// CheckName tells whether name can be the name of an extension, it becomes
// a folder name and a word after sshr
func CheckName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("name %q: use 1 to 31 lower case letters, digits and -, starting with a letter", name)
	}
	return nil
}

// checkArgv refuses a command whose first argument leaves the extension's
// folder or is an absolute path, so what is run is what was installed and
// pinned
func checkArgv(argv []string) error {
	if len(argv) == 0 {
		return errors.New("is empty")
	}
	first := argv[0]
	if strings.ContainsAny(first, "\\") || path.IsAbs(first) || strings.HasPrefix(first, "-") {
		return fmt.Errorf("the program %q must be a relative path inside the folder", first)
	}
	if clean := path.Clean(first); clean == ".." || strings.HasPrefix(clean, "../") || clean == "." {
		return fmt.Errorf("the program %q must be a file inside the folder", first)
	}
	for _, part := range strings.Split(first, "/") {
		if part == ".git" {
			return fmt.Errorf("the program %q is under .git, which an install never carries", first)
		}
	}
	for _, a := range argv {
		if strings.ContainsRune(a, 0) {
			return errors.New("an argument holds a NUL byte")
		}
	}
	return nil
}

// Argv returns the command for goos, the one named for it or "default"
func (m Manifest) Argv(goos string) ([]string, error) {
	if argv, ok := m.Command[goos]; ok {
		return append([]string(nil), argv...), nil
	}
	if argv, ok := m.Command["default"]; ok {
		return append([]string(nil), argv...), nil
	}
	return nil, fmt.Errorf("extension %s has no command for %s", m.Name, goos)
}

// Has tells whether the extension has the kind
func (m Manifest) Has(kind string) bool {
	for _, k := range m.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}
