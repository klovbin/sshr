// Package archtest checks the package rules of docs/ARCHITECTURE.md, a new
// import between sshr packages fails here until the table and the doc say
// it is allowed
package archtest

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const module = "sshr.dev/"

// allowed lists the sshr packages each package may import, as in the
// Layers table of docs/ARCHITECTURE.md
var allowed = map[string][]string{
	"assets":              {},
	"internal/app":        {},
	"internal/syncproto":  {},
	"internal/clip":       {},
	"internal/i18n":       {},
	"internal/archtest":   {},
	"internal/syncclient": {"internal/app", "internal/syncproto"},
	"internal/syncserver": {"internal/syncproto"},
	"internal/api":        {"internal/app"},
	"internal/mcp":        {"internal/app"},
	"internal/ext":        {"internal/app"},
	"internal/desktop":    {"assets"},
	"internal/ui":         {"internal/app", "internal/clip", "internal/i18n", "assets"},
	"cmd/sshr-sync":       {"internal/app", "internal/syncserver"},
	"cmd/sshr": {"internal/app", "internal/api", "internal/mcp", "internal/ext", "internal/syncclient", "internal/ui",
		"internal/desktop", "internal/clip", "assets"},
}

func TestPackageRules(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, filepath.Dir(path))
		pkg := filepath.ToSlash(rel)
		found[pkg] = true
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		ok, known := allowed[pkg]
		if !known {
			t.Errorf("package %s is not in the rules, add it to allowed and to docs/ARCHITECTURE.md", pkg)
			return nil
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			dep, inModule := strings.CutPrefix(p, module)
			if !inModule {
				continue
			}
			if !contains(ok, dep) {
				t.Errorf("%s imports %s (%s), the rules do not allow it", pkg, dep, filepath.Base(path))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var stale []string
	for pkg := range allowed {
		if !found[pkg] && pkg != "internal/archtest" {
			stale = append(stale, pkg)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("rules for packages that no longer exist: %v", stale)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
