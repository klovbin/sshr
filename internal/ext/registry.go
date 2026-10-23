package ext

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"sshr.dev/internal/app"
)

// LockFile sits next to the manifest and is written by sshr at install, not
// by the author, it says where the extension came from and which files were
// installed
const LockFile = "sshr-ext.lock"

// treeMaxFiles and treeMaxBytes keep an extension folder small enough to be
// hashed at every run
const (
	treeMaxFiles = 500
	treeMaxBytes = 50 << 20
)

// Lock is what sshr recorded when it installed an extension
type Lock struct {
	// Source is the git URL or the folder it was installed from
	Source string `json:"source"`
	// Commit is the git commit that was checked out, empty for a folder
	Commit string `json:"commit,omitempty"`
	// Tree is the hash of every file of the folder at install, a run
	// refuses a folder that hashes to something else
	Tree string `json:"tree"`
}

// Installed is an extension found in the extensions folder
type Installed struct {
	Manifest
	// Dir is the folder of the extension
	Dir  string
	Lock Lock
}

// Registry is the folder the extensions are installed into
type Registry struct {
	Root string
}

// DefaultRegistry is ~/.sshr/extensions, it is not created until an
// extension is installed
func DefaultRegistry() (*Registry, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return &Registry{Root: filepath.Join(home, ".sshr", "extensions")}, nil
}

// ErrNotInstalled means there is no extension of that name
var ErrNotInstalled = errors.New("not_installed")

// ErrChanged means the files of an installed extension are not the ones that
// were installed
var ErrChanged = errors.New("ext_changed")

// Find returns the installed extension called name, the name is checked
// first so it cannot point out of the folder
func (r *Registry) Find(name string) (*Installed, error) {
	if CheckName(name) != nil {
		return nil, ErrNotInstalled
	}
	return r.load(filepath.Join(r.Root, name), name)
}

func (r *Registry) load(dir, name string) (*Installed, error) {
	info, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotInstalled
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("extension %s: %s is not a folder", name, dir)
	}
	data, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return nil, fmt.Errorf("extension %s: %v", name, err)
	}
	m, err := ParseManifest(data)
	if err != nil {
		return nil, fmt.Errorf("extension %s: %v", name, err)
	}
	if m.Name != name {
		return nil, fmt.Errorf("extension %s: the manifest says it is %s", name, m.Name)
	}
	var lock Lock
	b, err := os.ReadFile(filepath.Join(dir, LockFile))
	if err != nil {
		return nil, fmt.Errorf("extension %s: no %s, install it with sshr ext install", name, LockFile)
	}
	if err := json.Unmarshal(b, &lock); err != nil || lock.Tree == "" {
		return nil, fmt.Errorf("extension %s: %s is damaged, install it again", name, LockFile)
	}
	return &Installed{Manifest: m, Dir: dir, Lock: lock}, nil
}

// List returns the installed extensions by name, a folder that does not
// load is reported in problems and does not hide the others
func (r *Registry) List() (found []Installed, problems []error) {
	entries, err := os.ReadDir(r.Root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, []error{err}
	}
	for _, e := range entries {
		if CheckName(e.Name()) != nil {
			continue
		}
		inst, err := r.load(filepath.Join(r.Root, e.Name()), e.Name())
		if err != nil {
			problems = append(problems, err)
			continue
		}
		found = append(found, *inst)
	}
	return found, problems
}

// Verify refuses an extension whose files are not the ones installed, a
// pull in its folder or an edit by hand changes the hash, installing it
// again pins the new files
func (i *Installed) Verify() error {
	got, err := HashTree(i.Dir)
	if err != nil {
		return fmt.Errorf("extension %s: %v", i.Name, err)
	}
	if got != i.Lock.Tree {
		return fmt.Errorf("%w: extension %s is not the one that was installed, its files changed, install it again to trust them", ErrChanged, i.Name)
	}
	return nil
}

// WriteLock records the install next to the manifest
func WriteLock(dir string, l Lock) error {
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return app.WriteFileAtomic(filepath.Join(dir, LockFile), append(b, '\n'), 0o600)
}

// Remove deletes the installed extension called name
func (r *Registry) Remove(name string) error {
	if CheckName(name) != nil {
		return ErrNotInstalled
	}
	dir := filepath.Join(r.Root, name)
	info, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNotInstalled
	}
	if err != nil {
		return err
	}
	// a link in place of the folder would send RemoveAll to where it points
	if !info.IsDir() {
		return os.Remove(dir)
	}
	return os.RemoveAll(dir)
}

// HashTree hashes the files of an extension folder, their paths, whether
// they are executable and their content, only the lock file is left out, a
// .git folder is hashed like any other, so nothing can be added there
// unseen, a link, a device or any file that is not a plain one is refused
// because it could point to something installed nowhere, folders count
// toward the limit too
func HashTree(dir string) (string, error) {
	type item struct{ rel, sum string }
	var items []item
	var total int64
	entries := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." {
			return nil
		}
		if entries++; entries > treeMaxFiles {
			return fmt.Errorf("more than %d files and folders", treeMaxFiles)
		}
		if d.IsDir() {
			return nil
		}
		if rel == LockFile {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a plain file, links and special files are not allowed in an extension", rel)
		}
		total += info.Size()
		if total > treeMaxBytes {
			return fmt.Errorf("more than %d MiB of files", treeMaxBytes>>20)
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		mark := "-"
		if runtime.GOOS != "windows" && info.Mode()&0o111 != 0 {
			mark = "x"
		}
		items = append(items, item{filepath.ToSlash(rel) + "\x00" + mark, hex.EncodeToString(h.Sum(nil))})
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Slice(items, func(a, b int) bool { return items[a].rel < items[b].rel })
	all := sha256.New()
	for _, it := range items {
		fmt.Fprintf(all, "%s\x00%s\n", it.rel, it.sum)
	}
	return hex.EncodeToString(all.Sum(nil)), nil
}
