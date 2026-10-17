package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// exportHeader starts the file sshr writes, a file without it is not
// sshr's and is never overwritten
const exportHeader = "# Written by sshr, edits here are lost, change the hosts in sshr\n"

// ExportItem is one saved host and what the export did with it
type ExportItem struct {
	Name  string
	Alias string
	// Skipped says why the host is not in the file, empty when it is
	Skipped string
	// Note says what plain ssh cannot do for this host
	Note string
}

var (
	aliasBad = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
	// a host name or address, IPv6 included, nothing ssh would read as a
	// token, a quote or a second word
	exportHostRe = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
	exportUserRe = regexp.MustCompile(`^[A-Za-z0-9._@\\-]+$`)
)

// exportAlias turns a host name into a Host alias of ssh config
func exportAlias(name string) string {
	return strings.Trim(aliasBad.ReplaceAllString(name, "-"), "-.")
}

// exportPath quotes a path for ssh config, ssh expands %-tokens in
// IdentityFile and IdentityAgent, a literal % is doubled
func exportPath(p string) (string, error) {
	if strings.ContainsAny(p, "\"\r\n\t") || strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 }) {
		return "", fmt.Errorf("path %q cannot be written to ssh config", p)
	}
	return `"` + strings.ReplaceAll(p, "%", "%%") + `"`, nil
}

// userAliases lists the Host names of the user's ssh config without the
// file sshr writes, a saved host with one of those names stays out of the
// export, ssh takes the first value it reads and the export would shadow
// the user's own block
func (s *Store) userAliases() map[string]bool {
	out := map[string]bool{}
	path, err := userSSHConfig()
	if err != nil {
		return out
	}
	open := map[string]bool{}
	if s.SSHConfigOut != "" {
		abs, _ := filepath.Abs(s.SSHConfigOut)
		open[abs] = true
	}
	collectAliases(path, filepath.Dir(path), 0, open, func(a string) { out[strings.ToLower(a)] = true })
	return out
}

// WriteSSHConfig writes every saved host as a Host block of ssh config, so
// plain ssh, scp, rsync and editors reach them by name, a password or a key
// kept inside sshr does not leave it, such hosts get the address only
func (s *Store) WriteSSHConfig(w io.Writer) ([]ExportItem, error) {
	hosts, err := s.List()
	if err != nil {
		return nil, err
	}
	taken := s.userAliases()
	items := make([]ExportItem, len(hosts))
	aliasOf := map[string]string{}
	for i, h := range hosts {
		it := ExportItem{Name: h.Name, Alias: exportAlias(h.Name)}
		switch {
		case it.Alias == "":
			it.Skipped = "the name has no letters or digits to make a Host alias of"
		case taken[strings.ToLower(it.Alias)]:
			it.Skipped = "ssh config has Host " + it.Alias + " already"
		}
		if it.Skipped == "" {
			taken[strings.ToLower(it.Alias)] = true
			aliasOf[h.ID] = it.Alias
		}
		items[i] = it
	}
	var buf bytes.Buffer
	buf.WriteString(exportHeader)
	for i := range hosts {
		h := &hosts[i]
		it := &items[i]
		if it.Skipped != "" {
			continue
		}
		block, note, err := s.exportBlock(h, it.Alias, aliasOf)
		if err != nil {
			it.Skipped = err.Error()
			delete(aliasOf, h.ID)
			continue
		}
		it.Note = note
		buf.WriteString("\n" + block)
	}
	_, err = w.Write(buf.Bytes())
	return items, err
}

// exportBlock is the Host block of one host
func (s *Store) exportBlock(h *Host, alias string, aliasOf map[string]string) (block, note string, err error) {
	if !exportHostRe.MatchString(h.Host) {
		return "", "", fmt.Errorf("address %q cannot be written to ssh config", h.Host)
	}
	if h.User != "" && !exportUserRe.MatchString(h.User) {
		return "", "", fmt.Errorf("user %q cannot be written to ssh config", h.User)
	}
	var b strings.Builder
	line := func(k, v string) { fmt.Fprintf(&b, "  %s %s\n", k, v) }
	fmt.Fprintf(&b, "Host %s\n", alias)
	line("HostName", h.Host)
	if h.User != "" {
		line("User", h.User)
	}
	if h.Port != 0 && h.Port != 22 {
		line("Port", fmt.Sprint(h.Port))
	}
	switch {
	case h.Key != "":
		p, err := exportPath(h.Key)
		if err != nil {
			return "", "", err
		}
		line("IdentityFile", p)
		line("IdentitiesOnly", "yes")
	case h.KeyMode == KeyAgent:
		if sock := agentSocket(h.Agent); sock != "" {
			p, err := exportPath(sock)
			if err != nil {
				return "", "", err
			}
			line("IdentityAgent", p)
		}
		if h.KeyPub != "" {
			s.writePub(h)
			p, err := exportPath(s.pubPath(h))
			if err != nil {
				return "", "", err
			}
			line("IdentityFile", p)
			line("IdentitiesOnly", "yes")
		}
	case h.agentKey():
		note = "the key is kept in sshr, plain ssh does not get it, connect with sshr"
	case h.PasswordMode == PasswordSaved || h.PasswordMode == PasswordOnePassword || h.PasswordMode == PasswordBitwarden:
		note = "the password is kept in sshr, plain ssh asks for it"
	}
	if parts := SplitJump(h.Jump); len(parts) > 0 {
		var hops []string
		for _, p := range parts {
			hop, saved, err := s.resolveHop(p)
			if err != nil {
				return "", "", err
			}
			if !saved {
				hops = append(hops, p)
				continue
			}
			a, ok := aliasOf[hop.ID]
			if !ok {
				return "", "", fmt.Errorf("jump host %s is not in the export", hop.Name)
			}
			hops = append(hops, a)
		}
		line("ProxyJump", strings.Join(hops, ","))
	}
	if note != "" {
		fmt.Fprintf(&b, "  # %s\n", note)
	}
	return b.String(), note, nil
}

// includeLine is the line of ~/.ssh/config that reads the export
func (s *Store) includeLine() string {
	p := s.SSHConfigOut
	// "~/" is read the same by Windows OpenSSH and by the msys ssh of Git
	// for Windows, which takes C:/... as relative to ~/.ssh, both paths
	// are resolved first, Windows may give one of them as a short 8.3
	// name (C:\Users\RUNNER~1) and a link on Linux hides the home prefix
	if home, err := os.UserHomeDir(); err == nil {
		if rel, err := filepath.Rel(realPath(home), realPath(p)); err == nil && !strings.HasPrefix(rel, "..") {
			p = "~/" + filepath.ToSlash(rel)
		}
	}
	// ssh reads a backslash in its config as an escape
	p = filepath.ToSlash(p)
	if strings.ContainsAny(p, " \t") {
		p = `"` + p + `"`
	}
	return "Include " + p
}

// realPath resolves links and short names of p, or of its folder when p
// does not exist yet
func realPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	if r, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
		return filepath.Join(r, filepath.Base(p))
	}
	return p
}

// ErrSSHConfigLink means ~/.ssh/config is a link, it is managed by
// something else (home-manager, a dotfiles repo) and sshr does not edit it
var ErrSSHConfigLink = errors.New("ssh_config_link")

// SSHConfigExported tells whether the export is installed, then every
// change of the hosts rewrites it
func (s *Store) SSHConfigExported() bool {
	if s.SSHConfigOut == "" {
		return false
	}
	b, err := os.ReadFile(s.SSHConfigOut)
	return err == nil && bytes.HasPrefix(b, []byte(exportHeader))
}

// InstallSSHConfig writes the export and adds its Include line to the top
// of ~/.ssh/config, at the top because a Host line before it would make
// ssh read the Include as part of that block, the hosts are rewritten on
// every change from then on
func (s *Store) InstallSSHConfig() ([]ExportItem, error) {
	if s.SSHConfigOut == "" {
		return nil, errors.New("this store has no ssh config export path")
	}
	items, err := s.refreshSSHConfig(true)
	if err != nil {
		return items, err
	}
	return items, s.editUserConfig(true)
}

// UninstallSSHConfig removes the Include line and the export file
func (s *Store) UninstallSSHConfig() error {
	if err := s.editUserConfig(false); err != nil && !errors.Is(err, ErrSSHConfigLink) {
		return err
	}
	if s.SSHConfigExported() {
		return os.Remove(s.SSHConfigOut)
	}
	return nil
}

// refreshSSHConfig rewrites the export file, unless force it does so only
// when the export is installed
func (s *Store) refreshSSHConfig(force bool) ([]ExportItem, error) {
	if s.SSHConfigOut == "" || (!force && !s.SSHConfigExported()) {
		return nil, nil
	}
	if b, err := os.ReadFile(s.SSHConfigOut); err == nil && !bytes.HasPrefix(b, []byte(exportHeader)) {
		return nil, fmt.Errorf("%s was not written by sshr, it is left as it is", s.SSHConfigOut)
	}
	var buf bytes.Buffer
	items, err := s.WriteSSHConfig(&buf)
	if err != nil {
		return items, err
	}
	return items, writeFileAtomic(s.SSHConfigOut, buf.Bytes(), 0o600)
}

// editUserConfig adds or removes the Include line of the export
func (s *Store) editUserConfig(add bool) error {
	path, err := userSSHConfig()
	if err != nil {
		return err
	}
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a link, add this line at its top yourself: %s", ErrSSHConfigLink, path, s.includeLine())
	}
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	want := s.includeLine()
	var kept []string
	found := false
	// split by hand, bufio.Scanner stops at a line over 64 KiB and the
	// rewrite would drop the rest of the file
	var lines []string
	if text := strings.TrimSuffix(string(old), "\n"); text != "" {
		lines = strings.Split(text, "\n")
	}
	for _, line := range lines {
		if strings.TrimSpace(line) == want {
			found = true
			if !add {
				continue
			}
		}
		kept = append(kept, line)
	}
	if add == found {
		return nil
	}
	if add {
		kept = append([]string{want}, kept...)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	out := strings.Join(kept, "\n")
	if out != "" {
		out += "\n"
	}
	return writeFileAtomic(path, []byte(out), mode)
}

// writeFileAtomic writes through a temporary file, a reader never sees half
// of it
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".sshr-tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
