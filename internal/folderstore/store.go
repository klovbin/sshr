// Package folderstore keeps a sync account in a plain folder that
// Syncthing, Dropbox, iCloud Drive or a network share already syncs
// between the devices of one person, it needs no server and no
// credential, the folder sees only what any store sees, ciphertext, the
// names of the devices and when they sync
//
// A synced folder has no compare and swap between devices: two devices
// that write the same change while they do not see each other both
// succeed, the sync tool keeps one file and turns the other into a
// conflict copy or drops it, Create is atomic on this machine only, the
// client finds such a fork through the head (syncclient.ErrFork) and this
// store refuses to go on while a conflict copy of a change lies in the
// folder
package folderstore

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sshr.dev/internal/syncclient"
)

// Config says where the account lives, the folder needs no secret
type Config struct {
	Path string `json:"path"`
}

// Store is a syncclient.ObjectStore in a folder, the folder is opened for
// each operation and let go after it, Windows would keep a folder that a
// long running sshr holds open from being moved or deleted
type Store struct {
	dir string
}

// nameRe is every name an account uses, a file of another shape is not
// read, written or listed, so a folder with junk, conflict copies or a
// planted link to elsewhere gives nothing but those names
var nameRe = regexp.MustCompile(`^(account|devices/[0-9a-f]{32}|envelopes/[0-9a-f]{32}/[0-9]{10}|blobs/[0-9a-f]{64}|manifests/[0-9]{20}|probe/[0-9a-f]{16})$`)

// tmpPrefix starts the name of a file being written, it never matches
// nameRe
const tmpPrefix = ".sshr-"

// topDirs are the folders of an account, a walk enters no other, a sync
// tool keeps its own (.stversions, .dropbox.cache) next to them
var topDirs = map[string]bool{"devices": true, "envelopes": true, "blobs": true, "manifests": true, "probe": true}

const (
	// walkMax bounds the entries one walk looks at, an account holds a few
	// thousand, a folder filled with junk must not take the memory
	walkMax = 100000
	// tmpAge is when a temporary file of a run that died is swept
	tmpAge = time.Hour
	// conflictsMax is how many conflict copies are named
	conflictsMax = 6
)

// New opens the folder of cfg, it must exist, sshr does not make the
// folder a sync tool shares
func New(cfg Config) (*Store, error) {
	if cfg.Path == "" || !filepath.IsAbs(cfg.Path) {
		return nil, errors.New("a folder store needs the full path of the folder")
	}
	fi, err := os.Stat(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("the sync folder %s: %v", cfg.Path, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a folder", cfg.Path)
	}
	return &Store{dir: cfg.Path}, nil
}

// open opens the folder, every path below goes through it and stays inside
func (s *Store) open() (*os.Root, error) { return os.OpenRoot(s.dir) }

func checkName(name string) (string, error) {
	if !nameRe.MatchString(name) {
		return "", fmt.Errorf("the folder store does not keep an object named %q", name)
	}
	return filepath.FromSlash(name), nil
}

// Get reads a regular file of at most max bytes, a link, a device or a
// pipe planted in the folder is refused, a file iCloud has moved off the
// machine is said to be so, not missing
func (s *Store) Get(name string, max int) ([]byte, error) {
	p, err := checkName(name)
	if err != nil {
		return nil, err
	}
	r, err := s.open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	fi, err := r.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		if s.evicted(r, name) {
			return nil, fmt.Errorf("%s is not downloaded to this machine, keep the sync folder downloaded", name)
		}
		return nil, syncclient.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s in the sync folder is not a plain file", name)
	}
	f, err := r.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// the file may have been swapped since the Lstat, only a plain file is
	// read, a pipe swapped in by a process of this machine could still
	// block the open, sync tools carry no pipes
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s in the sync folder is not a plain file", name)
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > max {
		return nil, syncclient.ErrTooLarge
	}
	return b, nil
}

// evicted tells whether iCloud keeps name as a placeholder .<name>.icloud
func (s *Store) evicted(r *os.Root, name string) bool {
	dir, base := path.Split(name)
	_, err := r.Lstat(filepath.FromSlash(dir + "." + base + ".icloud"))
	return err == nil
}

// writeTemp writes data to a new file next to name, synced to the disk,
// temporary files a run that died left in that folder go first, the sync
// tool would carry them to every device
func (s *Store) writeTemp(r *os.Root, p string, data []byte) (string, error) {
	dir := filepath.Dir(p)
	if dir != "." {
		if err := r.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
	}
	s.sweepTemp(r, dir)
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tmp := filepath.Join(dir, tmpPrefix+hex.EncodeToString(b)+".tmp")
	f, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		r.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

// sweepTemp removes the temporary files in dir older than tmpAge
func (s *Store) sweepTemp(r *os.Root, dir string) {
	entries, err := fs.ReadDir(r.FS(), filepath.ToSlash(dir))
	if err != nil {
		return
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), tmpPrefix) || !strings.HasSuffix(e.Name(), ".tmp") {
			continue
		}
		if fi, err := e.Info(); err == nil && fi.Mode().IsRegular() && time.Since(fi.ModTime()) > tmpAge {
			r.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// Put writes over any file of the name, a reader sees the old file or the
// new one
func (s *Store) Put(name string, data []byte) error {
	p, err := checkName(name)
	if err != nil {
		return err
	}
	r, err := s.open()
	if err != nil {
		return err
	}
	defer r.Close()
	tmp, err := s.writeTemp(r, p, data)
	if err != nil {
		return err
	}
	if err := r.Rename(tmp, p); err != nil {
		r.Remove(tmp)
		return err
	}
	return nil
}

// Create writes only when the name is free, a hard link of a complete
// file takes the name or fails when it is taken, a file system without
// hard links gets an exclusive create, a reader may see it half written
// for a moment there, the client takes that as an error and tries again,
// a run that dies in the middle there leaves a short file under the name,
// the client then refuses it and the person deletes it
func (s *Store) Create(name string, data []byte) error {
	p, err := checkName(name)
	if err != nil {
		return err
	}
	r, err := s.open()
	if err != nil {
		return err
	}
	defer r.Close()
	tmp, err := s.writeTemp(r, p, data)
	if err != nil {
		return err
	}
	defer r.Remove(tmp)
	err = r.Link(tmp, p)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fs.ErrExist):
		return syncclient.ErrExists
	}
	// exFAT, FAT and some SMB mounts have no hard links
	f, err := r.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return syncclient.ErrExists
	}
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		r.Remove(p)
	}
	return err
}

// Delete removes a file, a missing one is no error, a link is removed
// itself and never what it points at
func (s *Store) Delete(name string) error {
	p, err := checkName(name)
	if err != nil {
		return err
	}
	r, err := s.open()
	if err != nil {
		return err
	}
	defer r.Close()
	if err := r.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// walk calls fn with every file of the account folders as a slash path,
// folders that are links, hidden folders and folders an account does not
// have are not entered, at most walkMax entries are looked at
func (s *Store) walk(r *os.Root, fn func(name string, d fs.DirEntry)) error {
	seen := 0
	return fs.WalkDir(r.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if seen++; seen > walkMax {
			return fmt.Errorf("the sync folder holds more than %d entries, an account has a few thousand", walkMax)
		}
		if d.IsDir() {
			switch {
			case p == ".":
			case strings.HasPrefix(d.Name(), "."):
				return fs.SkipDir
			case !strings.Contains(p, "/") && !topDirs[p]:
				return fs.SkipDir
			case strings.Count(p, "/") >= 2:
				// an account is at most three levels deep
				return fs.SkipDir
			}
			return nil
		}
		fn(p, d)
		return nil
	})
}

// List names the objects that start with prefix, files of another shape
// are left out before they are counted, iCloud placeholders of changes
// are an error, the history would look shorter than it is
func (s *Store) List(prefix string) ([]string, error) {
	r, err := s.open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var out []string
	var evicted string
	err = s.walk(r, func(name string, d fs.DirEntry) {
		base := path.Base(name)
		if strings.HasPrefix(base, ".") && strings.HasSuffix(base, ".icloud") && (strings.HasPrefix(name, "manifests/") || name == ".account.icloud") {
			evicted = name
		}
		if d.Type().IsRegular() && nameRe.MatchString(name) && strings.HasPrefix(name, prefix) {
			out = append(out, name)
		}
	})
	if err != nil {
		return nil, err
	}
	if evicted != "" {
		return nil, fmt.Errorf("%s is not downloaded to this machine, keep the sync folder downloaded", evicted)
	}
	return out, nil
}

// conflictRe is a copy a sync tool made of a change or of the account:
// the name it had and more, Syncthing adds .sync-conflict-<time>-<id>,
// Dropbox " (conflicted copy ...)", iCloud " 2"
var conflictRe = regexp.MustCompile(`^(manifests/[0-9]{20}|account).+$`)

// Conflicts names the copies a sync tool made of the account or of a
// change when two devices wrote it at once, while one lies in the folder
// the account has forked and must not go on, sshr never deletes them, the
// person picks, other files are left alone, at most conflictsMax names
func (s *Store) Conflicts() ([]string, error) {
	r, err := s.open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var out []string
	err = s.walk(r, func(name string, d fs.DirEntry) {
		if len(out) < conflictsMax && !nameRe.MatchString(name) && conflictRe.MatchString(name) {
			out = append(out, name)
		}
	})
	return out, err
}

// Empty tells whether the folder holds no account yet, a second init in a
// folder that has one before it synced would mix two accounts
func (s *Store) Empty() (bool, error) {
	names, err := s.List("")
	return len(names) == 0, err
}
