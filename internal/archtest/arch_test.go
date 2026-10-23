// Package archtest checks the package rules of docs/ARCHITECTURE.md, a new
// import between sshr packages fails here until the table and the doc say
// it is allowed
package archtest

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	"internal/fileio":     {},
	"internal/record":     {},
	"internal/settings":   {"internal/fileio", "internal/record"},
	"internal/vault":      {"internal/fileio", "internal/settings"},
	"internal/hosts":      {"internal/fileio", "internal/record", "internal/vault"},
	"internal/health":     {"internal/hosts"},
	"internal/pwmgr":      {"internal/settings"},
	"internal/audit":      {"internal/fileio"},
	"internal/app":        {"internal/fileio", "internal/record", "internal/settings", "internal/vault", "internal/hosts", "internal/health", "internal/pwmgr"},
	"internal/syncproto":  {},
	"internal/clip":       {},
	"internal/i18n":       {},
	"internal/archtest":   {},
	"internal/syncclient": {"internal/fileio", "internal/record", "internal/vault", "internal/hosts", "internal/syncproto"},
	"internal/s3store":    {"internal/syncclient"},
	"internal/syncserver": {"internal/syncproto", "internal/fileio"},
	"internal/api":        {"internal/app", "internal/audit"},
	"internal/mcp":        {"internal/app", "internal/audit"},
	"internal/ext":        {"internal/app"},
	"internal/desktop":    {"assets", "internal/fileio"},
	"internal/ui":         {"internal/app", "internal/clip", "internal/i18n", "assets"},
	"cmd/sshr-sync":       {"internal/fileio", "internal/syncserver"},
	"cmd/sshr": {"internal/app", "internal/audit", "internal/api", "internal/mcp", "internal/ext", "internal/syncclient", "internal/ui",
		"internal/desktop", "internal/clip", "assets"},
}

// noExec lists the packages that start no program themselves, the GUI,
// the assistant and the sync server ask the core for anything that runs
var noExec = []string{"internal/ui", "internal/mcp", "internal/syncserver", "internal/syncclient",
	"internal/syncproto", "internal/fileio", "internal/record", "internal/settings", "internal/vault", "internal/hosts", "internal/health", "internal/s3store", "internal/audit", "internal/i18n", "assets", "cmd/sshr-sync"}

// phoneCore lists the packages a phone build links, os/exec is not in
// them even through another package, what runs ssh stays in app
var phoneCore = []string{"internal/syncproto", "internal/syncclient", "internal/s3store", "internal/fileio", "internal/record", "internal/settings", "internal/vault", "internal/hosts", "internal/health", "internal/i18n", "internal/syncserver", "cmd/sshr-sync"}

// gioOnly is the one package that may import Gio
const gioOnly = "internal/ui"

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
			if p == "os/exec" && contains(noExec, pkg) {
				t.Errorf("%s imports os/exec (%s), it runs no program itself", pkg, filepath.Base(path))
			}
			if strings.HasPrefix(p, "gioui.org") && pkg != gioOnly {
				t.Errorf("%s imports Gio (%s), only %s may", pkg, filepath.Base(path), gioOnly)
			}
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

// the packages of a phone build do not reach os/exec through any import,
// the go command lists every dependency
func TestPhoneCoreRunsNothing(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		gobin = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	args := []string{"list", "-tags", "nocgo", "-f", `{{.ImportPath}} {{join .Deps " "}}`}
	for _, p := range phoneCore {
		args = append(args, module+p)
	}
	cmd := exec.Command(gobin, args...)
	cmd.Dir = "../.."
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && contains(fields[1:], "os/exec") {
			t.Errorf("%s reaches os/exec, a phone build cannot run programs", fields[0])
		}
	}
}
