package ext

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Staged is an extension fetched into a temporary folder and checked, not
// installed yet, the caller shows it to the user and installs it or throws
// it away, nothing in it has been run
type Staged struct {
	Manifest
	// Lock is what will be recorded: the source, the commit and the hash
	Lock Lock
	// Files is how many files the extension has
	Files int

	tmp   string
	files string
}

// Discard removes the temporary folder
func (s *Staged) Discard() { os.RemoveAll(s.tmp) }

var scpURL = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[^\s]+$`)

// isGitURL tells an address git fetches from a folder on this machine, only
// https and ssh are taken, ext:: and file:// transports run programs or read
// folders git was not asked about, a leading - would be an option
func isGitURL(s string) bool {
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "ssh://") || scpURL.MatchString(s)
}

// Prepare fetches the extension at source, a git URL or a folder, into a
// temporary folder and checks it: the manifest, plain files only, the size
// limits, a git clone is made shallow and none of its files is run, the .git
// folder is not kept, the commit is recorded
func Prepare(source string) (*Staged, error) { return prepare(source, "") }

// PrepareAt is Prepare of the git URL url at commit, a catalog entry names
// the commit it was checked at and nothing newer is installed from it
func PrepareAt(url, commit string) (*Staged, error) {
	if !isGitURL(url) {
		return nil, fmt.Errorf("%q is not an https or ssh git address", url)
	}
	if !commitRe.MatchString(commit) {
		return nil, fmt.Errorf("%q is not a full git commit hash", commit)
	}
	return prepare(url, commit)
}

var commitRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

func prepare(source, commit string) (*Staged, error) {
	if strings.HasPrefix(source, "-") {
		return nil, fmt.Errorf("%q is not a folder or a git address", source)
	}
	tmp, err := os.MkdirTemp("", "sshr-ext-")
	if err != nil {
		return nil, err
	}
	s := &Staged{tmp: tmp, files: filepath.Join(tmp, "files")}
	fail := func(err error) (*Staged, error) {
		s.Discard()
		return nil, err
	}
	from := source
	switch {
	case isGitURL(source):
		clone := filepath.Join(tmp, "clone")
		got, err := cloneGit(source, clone, commit)
		if err != nil {
			return fail(err)
		}
		from, s.Lock.Commit = clone, got
	default:
		abs, err := filepath.Abs(source)
		if err != nil {
			return fail(err)
		}
		info, err := os.Stat(abs)
		if err != nil || !info.IsDir() {
			return fail(fmt.Errorf("%q is neither a folder nor an https or ssh git address", source))
		}
		// the full path, so the record and the install screen say which
		// folder it was and not a bare word that reads like a catalog name
		from, source = abs, abs
	}
	s.Lock.Source = source
	if s.Files, err = copyTree(from, s.files); err != nil {
		return fail(err)
	}
	data, err := os.ReadFile(filepath.Join(s.files, ManifestFile))
	if err != nil {
		return fail(fmt.Errorf("no %s in %s, an extension needs one", ManifestFile, source))
	}
	if s.Manifest, err = ParseManifest(data); err != nil {
		return fail(err)
	}
	if s.Lock.Tree, err = HashTree(s.files); err != nil {
		return fail(err)
	}
	return s, nil
}

// cloneTimeout is how long a clone may take, a server that sends a byte now
// and then would otherwise hold sshr for good
var cloneTimeout = 60 * time.Second

// gitSafe are the options of every git run on a clone: only https and ssh,
// no hooks, templates or git-lfs filters of the user
var gitSafe = []string{
	"-c", "core.hooksPath=" + os.DevNull,
	"-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "protocol.ssh.allow=always",
	"-c", "filter.lfs.smudge=", "-c", "filter.lfs.process=", "-c", "filter.lfs.required=false",
}

// runGit runs git with gitSafe and args under the clone timeout
func runGit(what string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cloneTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append(append([]string{}, gitSafe...), args...)...)
	cmd.Env = gitEnv(os.Environ())
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return fmt.Errorf("%s did not finish in %s", what, cloneTimeout)
	}
	if err != nil {
		return fmt.Errorf("%s failed: %s", what, strings.TrimSpace(string(out)))
	}
	return nil
}

// cloneGit fetches the newest commit of url into dest, or commit when it is
// set, and returns the hash checked out, git gets the environment without
// secrets, no prompt on any terminal, blobs over 5 MiB are not downloaded,
// and git runs no file of the clone, a commit that is not the newest is
// fetched by its hash afterwards, which works with every git version
func cloneGit(url, dest, commit string) (string, error) {
	if err := runGit("git clone "+url, "clone", "--depth", "1", "--no-tags", "--single-branch", "--no-recurse-submodules",
		"--filter=blob:limit=5m", "--template=", "--", url, dest); err != nil {
		return "", err
	}
	head, err := revParse(dest)
	if err != nil || commit == "" || head == commit {
		return head, err
	}
	if err := runGit("git fetch of commit "+commit, "-C", dest, "fetch", "--depth", "1", "--no-tags",
		"--filter=blob:limit=5m", "origin", commit); err != nil {
		return "", err
	}
	// FETCH_HEAD is the object just fetched, a branch named like the hash
	// would win over the hash itself
	if err := runGit("git checkout of commit "+commit, "-C", dest, "checkout", "--quiet", "--detach", "FETCH_HEAD"); err != nil {
		return "", err
	}
	if head, err = revParse(dest); err != nil {
		return "", err
	}
	if head != commit {
		return "", fmt.Errorf("%s does not hold commit %s, the catalog entry is wrong or the repository changed", url, commit)
	}
	return head, nil
}

// revParse is the commit checked out in dest
func revParse(dest string) (string, error) {
	rev := exec.Command("git", "-C", dest, "rev-parse", "HEAD")
	rev.Env = gitEnv(os.Environ())
	commit, err := rev.Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse in the clone failed: %v", err)
	}
	return strings.TrimSpace(string(commit)), nil
}

// gitEnv is the environment of git: no secrets, no question on the terminal,
// ssh in batch mode unless the user chose their own ssh command
func gitEnv(parent []string) []string {
	env := append(cleanEnv(parent), "GIT_TERMINAL_PROMPT=0", "GIT_ALLOW_PROTOCOL=https:ssh")
	for _, kv := range env {
		if strings.HasPrefix(kv, "GIT_SSH_COMMAND=") {
			return env
		}
	}
	return append(env, "GIT_SSH_COMMAND=ssh -o BatchMode=yes")
}

// copyTree copies a folder of plain files and returns how many, .git is left
// out, a link or special file is refused, the executable bit is kept
func copyTree(from, to string) (int, error) {
	if err := os.MkdirAll(to, 0o700); err != nil {
		return 0, err
	}
	files, entries := 0, 0
	var total int64
	err := filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		if rel == "." {
			return nil
		}
		dest := filepath.Join(to, rel)
		if d.IsDir() {
			// the history of a clone is not part of the extension, HashTree
			// counts a .git folder, so none is installed
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			if entries++; entries > treeMaxFiles {
				return fmt.Errorf("more than %d files and folders", treeMaxFiles)
			}
			return os.MkdirAll(dest, 0o700)
		}
		if entries++; entries > treeMaxFiles {
			return fmt.Errorf("more than %d files and folders", treeMaxFiles)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a plain file, links and special files are not allowed in an extension", rel)
		}
		files++
		if total += info.Size(); total > treeMaxBytes {
			return fmt.Errorf("more than %d MiB of files", treeMaxBytes>>20)
		}
		mode := os.FileMode(0o600)
		if info.Mode()&0o111 != 0 {
			mode = 0o700
		}
		return copyFile(p, dest, mode)
	})
	return files, err
}

func copyFile(from, to string, mode os.FileMode) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// Install puts a staged extension into the registry and pins it, an
// extension of the same name is replaced, which is also how the files of a
// changed one are trusted again, the new folder is built beside the old one
// and swapped in, then pinned, a failure before the pin leaves a folder that
// is not trusted and never one that runs unchecked
func (r *Registry) Install(s *Staged) error {
	if err := CheckName(s.Name); err != nil {
		return err
	}
	return r.locked(func() error {
		if err := r.pinsWritable(); err != nil {
			return err
		}
		fresh := filepath.Join(r.Root, "."+s.Name+".new")
		old := filepath.Join(r.Root, "."+s.Name+".old")
		dest := filepath.Join(r.Root, s.Name)
		os.RemoveAll(fresh)
		os.RemoveAll(old)
		if _, err := copyTree(s.files, fresh); err != nil {
			os.RemoveAll(fresh)
			return err
		}
		if got, err := HashTree(fresh); err != nil || got != s.Lock.Tree {
			os.RemoveAll(fresh)
			return fmt.Errorf("the copy of %s does not match what was checked, nothing is installed", s.Name)
		}
		replaced := false
		if _, err := os.Lstat(dest); err == nil {
			if err := os.Rename(dest, old); err != nil {
				os.RemoveAll(fresh)
				return err
			}
			replaced = true
		}
		if err := os.Rename(fresh, dest); err != nil {
			if replaced {
				os.Rename(old, dest)
			}
			os.RemoveAll(fresh)
			return err
		}
		os.RemoveAll(old)
		pins, err := r.pins()
		if err != nil {
			return err
		}
		pins[s.Name] = s.Lock
		return r.writePins(pins)
	})
}
