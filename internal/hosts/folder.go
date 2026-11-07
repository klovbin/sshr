package hosts

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"sshr.dev/internal/fileio"
)

const (
	foldersFile   = "folders.json"
	maxFolderSegs = 8
	maxFolderLen  = 64
)

// foldersDoc is the empty-folder registry next to the host files
type foldersDoc struct {
	Folders []string `json:"folders"`
}

// CleanFolder lower-cases a folder path, splits on "/", and checks each
// segment the same way as a tag, empty means the root list
func CleanFolder(s string) (string, error) {
	s = strings.Trim(strings.ToLower(strings.TrimSpace(s)), "/")
	if s == "" {
		return "", nil
	}
	parts := strings.Split(s, "/")
	if len(parts) > maxFolderSegs {
		return "", fmt.Errorf("a folder path has at most %d segments", maxFolderSegs)
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || p == "." || p == ".." {
			return "", fmt.Errorf("folder %q: empty or relative segments are not allowed", s)
		}
		if len(p) > maxFolderLen || !tagRe.MatchString(p) {
			return "", fmt.Errorf("folder segment %q: use letters, digits, '.', '_' and '-', up to %d characters", p, maxFolderLen)
		}
		out = append(out, p)
	}
	return strings.Join(out, "/"), nil
}

// ListFolders is every folder path: the registry plus folders hosts sit in,
// sorted
func (s *Store) ListFolders() ([]string, error) {
	var out []string
	err := s.locked(func(tx *Store) error {
		var err error
		out, err = tx.listFolders()
		return err
	})
	return out, err
}

func (s *Store) listFolders() ([]string, error) {
	seen := map[string]bool{}
	reg, err := s.readFolders()
	if err != nil {
		return nil, err
	}
	for _, f := range reg {
		seen[f] = true
	}
	hosts, err := s.List()
	if err != nil {
		return nil, err
	}
	for _, h := range hosts {
		if h.Folder != "" {
			seen[h.Folder] = true
			// parent paths of nested folders also show as folders
			for _, p := range folderParents(h.Folder) {
				seen[p] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out, nil
}

// AddFolder registers an empty folder path
func (s *Store) AddFolder(path string) (string, error) {
	var out string
	err := s.locked(func(tx *Store) error {
		var err error
		out, err = tx.addFolder(path)
		return err
	})
	return out, err
}

func (s *Store) addFolder(path string) (string, error) {
	path, err := CleanFolder(path)
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", fmt.Errorf("folder name is empty")
	}
	reg, err := s.readFolders()
	if err != nil {
		return "", err
	}
	for _, f := range reg {
		if f == path {
			return path, nil
		}
	}
	reg = append(reg, path)
	sort.Strings(reg)
	if err := s.writeFolders(reg); err != nil {
		return "", err
	}
	s.changed()
	return path, nil
}

// RemoveFolder drops path from the registry and, when force, moves every
// host in that folder (or under it) to the root list; without force it
// refuses when a host still sits there
func (s *Store) RemoveFolder(path string, force bool) error {
	return s.locked(func(tx *Store) error {
		return tx.removeFolder(path, force)
	})
}

func (s *Store) removeFolder(path string, force bool) error {
	path, err := CleanFolder(path)
	if err != nil {
		return err
	}
	if path == "" {
		return fmt.Errorf("folder name is empty")
	}
	hosts, err := s.List()
	if err != nil {
		return err
	}
	var inFolder []Host
	for _, h := range hosts {
		if h.Folder == path || strings.HasPrefix(h.Folder, path+"/") {
			inFolder = append(inFolder, h)
		}
	}
	if len(inFolder) > 0 && !force {
		return fmt.Errorf("folder %q still has %d host(s); move them out or pass --force", path, len(inFolder))
	}
	for i := range inFolder {
		in := inFolder[i]
		in.Folder, in.Rev = "", 0
		if _, err := s.update(in.ID, in, false); err != nil {
			return err
		}
	}
	reg, err := s.readFolders()
	if err != nil {
		return err
	}
	kept := reg[:0]
	for _, f := range reg {
		if f == path || strings.HasPrefix(f, path+"/") {
			continue
		}
		kept = append(kept, f)
	}
	if err := s.writeFolders(kept); err != nil {
		return err
	}
	s.changed()
	return nil
}

func (s *Store) readFolders() ([]string, error) {
	b, err := fileio.ReadFileShared(filepath.Join(s.Dir, foldersFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var doc foldersDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("folders.json: %w", err)
	}
	var out []string
	seen := map[string]bool{}
	for _, f := range doc.Folders {
		f, err := CleanFolder(f)
		if err != nil || f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	sort.Strings(out)
	return out, nil
}

func (s *Store) writeFolders(folders []string) error {
	if len(folders) == 0 {
		err := os.Remove(filepath.Join(s.Dir, foldersFile))
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	b, err := json.MarshalIndent(foldersDoc{Folders: folders}, "", "  ")
	if err != nil {
		return err
	}
	return fileio.WriteFile(filepath.Join(s.Dir, foldersFile), append(b, '\n'), 0o600)
}

// folderParents are the parent paths of a nested folder ("a/b/c" → a, a/b)
func folderParents(path string) []string {
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return nil
	}
	var out []string
	for i := 1; i < len(parts); i++ {
		out = append(out, strings.Join(parts[:i], "/"))
	}
	return out
}
