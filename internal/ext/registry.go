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
	"reflect"
	"runtime"
	"sort"
	"time"

	"sshr.dev/internal/app"
)

// PinsFile sits in the extensions folder next to the folders of the
// extensions, written by sshr at install, it says where each extension came
// from and which files were installed, a pin inside the folder would be
// supplied by whoever supplies the folder
const PinsFile = ".pins.json"

// pinsMaxBytes bounds the file that is read at every run
const pinsMaxBytes = 1 << 20

// lockWait is how long an install or a removal waits for another one
const lockWait = 10 * time.Second

// treeMaxFiles and treeMaxBytes keep an extension folder small enough to be
// hashed at every run
const (
	treeMaxFiles = 500
	treeMaxBytes = 50 << 20
)

// Lock is the pin of an installed extension, what sshr recorded when it
// installed it
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
	// Dir is the folder of the extension, its files are pinned
	Dir string
	// Data is the folder it may write to, state and caches go there
	Data string
	Lock Lock
}

// Registry is the folder the extensions are installed into
type Registry struct {
	Root string
	// DataRoot holds one folder per extension to write to, empty means
	// .data inside Root
	DataRoot string
}

// dataDir is the folder extension name may write to, it stays when the
// extension is removed, so a new install keeps its state
func (r *Registry) dataDir(name string) string {
	if r.DataRoot != "" {
		return filepath.Join(r.DataRoot, name)
	}
	return filepath.Join(r.Root, ".data", name)
}

// DefaultRegistry is ~/.sshr/extensions, it is not created until an
// extension is installed
func DefaultRegistry() (*Registry, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return &Registry{
		Root:     filepath.Join(home, ".sshr", "extensions"),
		DataRoot: filepath.Join(home, ".sshr", "extension-data"),
	}, nil
}

// ErrNotInstalled means there is no extension of that name
var ErrNotInstalled = errors.New("not_installed")

// ErrChanged means the files of an installed extension are not the ones that
// were installed
var ErrChanged = errors.New("ext_changed")

// pins reads the pin of every installed extension, none yet is an empty list
func (r *Registry) pins() (map[string]Lock, error) {
	path := filepath.Join(r.Root, PinsFile)
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]Lock{}, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > pinsMaxBytes {
		return nil, fmt.Errorf("%s is not a plain file of a sensible size, remove it and install the extensions again", path)
	}
	b, err := app.ReadFileShared(path)
	if err != nil {
		return nil, err
	}
	var file struct {
		Extensions map[string]Lock `json:"extensions"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		if _, format, ferr := app.RecordExtra(b, reflect.TypeOf(pinsFile{})); ferr == nil && format > pinsFormat {
			return nil, fmt.Errorf("%w: %s was written by a newer sshr (format %d), update sshr to use the extensions", app.ErrNewerFormat, path, format)
		}
		return nil, fmt.Errorf("%s is damaged, remove it and install the extensions again: %v", path, err)
	}
	if file.Extensions == nil {
		file.Extensions = map[string]Lock{}
	}
	return file.Extensions, nil
}

// pinsFormat is the format of .pins.json this build writes, a file without
// "version" is format 1
const pinsFormat = 1

// pinsFile is .pins.json as it is on disk, a pin is kept as raw JSON so a
// pin this build did not change keeps the fields a newer sshr wrote in it
type pinsFile struct {
	Extensions map[string]json.RawMessage `json:"extensions"`
}

// pinsWritable fails when .pins.json was written by a newer sshr, an
// install or a removal checks it before it touches any folder
func (r *Registry) pinsWritable() error {
	path := filepath.Join(r.Root, PinsFile)
	b, err := app.ReadFileShared(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, format, err := app.RecordExtra(b, reflect.TypeOf(pinsFile{})); err == nil && format > pinsFormat {
		return fmt.Errorf("%w: %s was written by a newer sshr (format %d), update sshr to install or remove extensions", app.ErrNewerFormat, path, format)
	}
	return nil
}

// writePins writes the pins, the keys and pins of a newer sshr that this
// write does not change are kept, a file of a newer format is not written
func (r *Registry) writePins(pins map[string]Lock) error {
	path := filepath.Join(r.Root, PinsFile)
	var old pinsFile
	var extra map[string]json.RawMessage
	if b, err := app.ReadFileShared(path); err == nil {
		var format int
		if extra, format, err = app.RecordExtra(b, reflect.TypeOf(pinsFile{})); err == nil && format > pinsFormat {
			return fmt.Errorf("%w: %s was written by a newer sshr (format %d), update sshr to install or remove extensions", app.ErrNewerFormat, path, format)
		}
		json.Unmarshal(b, &old)
	}
	out := pinsFile{Extensions: map[string]json.RawMessage{}}
	for name, l := range pins {
		var was Lock
		if raw, ok := old.Extensions[name]; ok && json.Unmarshal(raw, &was) == nil && was == l {
			out.Extensions[name] = raw
			continue
		}
		b, err := json.Marshal(l)
		if err != nil {
			return err
		}
		out.Extensions[name] = b
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if b, err = app.AppendRecordKeys(b, extra); err != nil {
		return err
	}
	return app.WriteFileAtomic(path, append(b, '\n'), 0o600)
}

// Pin records the install of the extension called name, one at a time with
// other installs and removals
func (r *Registry) Pin(name string, l Lock) error {
	return r.locked(func() error {
		pins, err := r.pins()
		if err != nil {
			return err
		}
		pins[name] = l
		return r.writePins(pins)
	})
}

// locked runs fn with the lock of the extensions folder, installs and
// removals of different processes do not interleave
func (r *Registry) locked(fn func() error) error {
	if err := os.MkdirAll(r.Root, 0o700); err != nil {
		return err
	}
	unlock, err := app.WaitLock(filepath.Join(r.Root, ".lock"), "changing extensions", lockWait)
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

// Find returns the installed extension called name, the name is checked
// first so it cannot point out of the folder
func (r *Registry) Find(name string) (*Installed, error) {
	if CheckName(name) != nil {
		return nil, ErrNotInstalled
	}
	pins, err := r.pins()
	if err != nil {
		return nil, err
	}
	return r.load(filepath.Join(r.Root, name), name, pins)
}

func (r *Registry) load(dir, name string, pins map[string]Lock) (*Installed, error) {
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
	lock, ok := pins[name]
	if !ok || lock.Tree == "" {
		return nil, fmt.Errorf("extension %s: the folder was not installed by sshr ext install and is not trusted, install it from its source to use it", name)
	}
	return &Installed{Manifest: m, Dir: dir, Data: r.dataDir(name), Lock: lock}, nil
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
	pins, err := r.pins()
	if err != nil {
		return nil, []error{err}
	}
	for _, e := range entries {
		if CheckName(e.Name()) != nil {
			continue
		}
		inst, err := r.load(filepath.Join(r.Root, e.Name()), e.Name(), pins)
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

// Remove deletes the installed extension called name and its pin, a folder
// that was never installed is removed too
func (r *Registry) Remove(name string) error {
	if CheckName(name) != nil {
		return ErrNotInstalled
	}
	return r.locked(func() error {
		if err := r.pinsWritable(); err != nil {
			return err
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
			err = os.Remove(dir)
		} else {
			err = os.RemoveAll(dir)
		}
		if err != nil {
			return err
		}
		pins, err := r.pins()
		if err != nil {
			return err
		}
		if _, ok := pins[name]; !ok {
			return nil
		}
		delete(pins, name)
		return r.writePins(pins)
	})
}

// HashTree hashes the files of an extension folder, their paths, whether
// they are executable and their content, a .git folder is hashed like any
// other, so nothing can be added there unseen, a link, a device or any file that is not a plain one is refused
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
