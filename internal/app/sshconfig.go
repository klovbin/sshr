package app

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// sshConfigFile is the config ssh -G reads, empty means the user's own
// (~/.ssh/config and what it includes), tests point it at a file of their
// own, never at a config the user did not write: Match exec runs commands
var sshConfigFile = ""

// userSSHConfig is the path of the user's ssh config
func userSSHConfig() (string, error) {
	if sshConfigFile != "" {
		return sshConfigFile, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "config"), nil
}

// SSHConfigAliases lists the Host names of the user's ssh config and the
// files it includes, patterns with *, ? or ! are skipped, they are not
// hosts, only rules for hosts
func SSHConfigAliases() ([]string, error) {
	path, err := userSSHConfig()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("there is no %s to import", path)
	}
	seen := map[string]bool{}
	var out []string
	err = collectAliases(path, filepath.Dir(path), 0, map[string]bool{}, func(a string) {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	})
	return out, err
}

// collectAliases reads one config file, a relative Include is resolved
// against ~/.ssh, a file that includes itself is read once
func collectAliases(path, base string, depth int, open map[string]bool, add func(string)) error {
	if depth > 16 {
		return fmt.Errorf("%s: Include goes deeper than 16 files", path)
	}
	abs, _ := filepath.Abs(path)
	if open[abs] {
		return nil
	}
	open[abs] = true
	defer delete(open, abs)
	// sshr itself rewrites ~/.ssh/config and the export, on Windows a read
	// during that fails unless it waits
	data, err := ReadFileShared(path)
	if err != nil {
		if os.IsNotExist(err) && depth > 0 {
			return nil
		}
		return err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, args := configLine(sc.Text())
		switch key {
		case "host":
			for _, a := range args {
				if a != "" && !strings.ContainsAny(a, "*?!") {
					add(a)
				}
			}
		case "include":
			for _, pat := range args {
				pat = ExpandHome(pat)
				if !filepath.IsAbs(pat) {
					pat = filepath.Join(base, pat)
				}
				files, _ := filepath.Glob(pat)
				sort.Strings(files)
				for _, inc := range files {
					if err := collectAliases(inc, base, depth+1, open, add); err != nil {
						return err
					}
				}
			}
		}
	}
	return sc.Err()
}

// configLine splits "Key value value" or "Key=value", quotes group words
func configLine(line string) (string, []string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", nil
	}
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return strings.ToLower(line), nil
	}
	key := strings.ToLower(line[:i])
	rest := strings.TrimLeft(line[i:], " \t=")
	var args []string
	var cur strings.Builder
	quoted := false
	for _, r := range rest {
		switch {
		case r == '"':
			quoted = !quoted
		case (r == ' ' || r == '\t') && !quoted:
			if cur.Len() > 0 {
				args = append(args, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		args = append(args, cur.String())
	}
	return key, args
}

// sshG returns what ssh would use for alias, nothing is sent over the
// network, keys are lower case, a key may repeat
func sshG(alias string, config string) (map[string][]string, error) {
	args := []string{"-G"}
	if config != "" {
		args = append(args, "-F", config)
	}
	cmd := exec.Command("ssh", append(args, "--", alias)...)
	cmd.Stdin = nil
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("ssh -G %s: %s", alias, msg)
	}
	m := map[string][]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), " ")
		if ok {
			k = strings.ToLower(k)
			m[k] = append(m[k], v)
		}
	}
	return m, nil
}

// unbracket turns ssh -G's "[localhost]" back into "localhost", an IPv6
// address keeps its brackets
func unbracket(s string) string {
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") && !strings.Contains(s, ":") {
		return s[1 : len(s)-1]
	}
	return s
}

// splitAddr splits "[bind]:port" or "port" as ssh -G prints it
func splitAddr(s string) (host, port string) {
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.HasSuffix(s, "]") {
		return unbracket(s[:i]), s[i+1:]
	}
	return "", s
}

// forwardFromG turns a forward line of ssh -G into a sshr forward, unix
// socket forwards are not supported and return false
func forwardFromG(kind, value string, n int) (Forward, bool) {
	fields := strings.Fields(value)
	name := fmt.Sprintf("%s%d", strings.ToLower(kind), n)
	if kind == "D" {
		if len(fields) != 1 {
			return Forward{}, false
		}
		bind, port := splitAddr(fields[0])
		spec := port
		if bind != "" {
			spec = bind + ":" + port
		}
		f := Forward{Name: name, Kind: "D", Spec: spec}
		return f, f.check() == nil
	}
	if len(fields) != 2 || strings.HasPrefix(fields[0], "/") || strings.HasPrefix(fields[1], "/") {
		return Forward{}, false
	}
	bind, port := splitAddr(fields[0])
	host, hport := splitAddr(fields[1])
	spec := port + ":" + host + ":" + hport
	if bind != "" {
		spec = bind + ":" + spec
	}
	f := Forward{Name: name, Kind: kind, Spec: spec}
	return f, f.check() == nil
}

// hostFromSSHConfig builds a sshr host for alias from what ssh -G says,
// defaults lists what ssh uses with no config at all, only what differs
// from it was set by the user, notes say what could not be carried over
func hostFromSSHConfig(alias string, g, defaults map[string][]string) (Host, []string) {
	first := func(k string) string {
		if v := g[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	h := Host{Name: alias, Host: first("hostname"), User: first("user")}
	h.Port, _ = strconv.Atoi(first("port"))
	var notes []string
	if strings.Join(g["identityfile"], "\n") != strings.Join(defaults["identityfile"], "\n") {
		for _, f := range g["identityfile"] {
			p := ExpandHome(f)
			if CheckPrivateKey(p) == nil {
				h.Key = p
				break
			}
		}
		if h.Key == "" {
			notes = append(notes, "IdentityFile "+strings.Join(g["identityfile"], ", ")+" not found or not a private key")
		}
	}
	if a := first("identityagent"); h.Key == "" && a != "" && a != "none" && a != "SSH_AUTH_SOCK" {
		h.KeyMode = KeyAgent
		h.Agent = a
		if one := ExpandHome(agentSocket(AgentOnePassword)); a == one || strings.HasSuffix(a, "/.1password/agent.sock") {
			h.Agent = AgentOnePassword
		}
	}
	if j := first("proxyjump"); j != "" && j != "none" {
		h.Jump = j
	}
	if pc := first("proxycommand"); pc != "" && pc != "none" {
		// the alias as the address makes ssh apply its config block again,
		// with the address ProxyCommand would be lost
		h.Host = alias
		notes = append(notes, "ProxyCommand stays in ssh config, sshr connects through the alias")
	}
	for kind, key := range map[string]string{"L": "localforward", "R": "remoteforward", "D": "dynamicforward"} {
		for i, v := range g[key] {
			if f, ok := forwardFromG(kind, v, i+1); ok {
				h.Forwards = append(h.Forwards, f)
			} else {
				notes = append(notes, "skipped "+key+" "+v)
			}
		}
	}
	sort.Slice(h.Forwards, func(i, j int) bool { return h.Forwards[i].Name < h.Forwards[j].Name })
	return h, notes
}

// sshDefaults is what ssh uses with no config at all, it reads an empty
// file, Windows OpenSSH cannot open NUL (os.DevNull) as a config
func sshDefaults() (map[string][]string, error) {
	f, err := os.CreateTemp("", "sshr-empty-config-*")
	if err != nil {
		return nil, err
	}
	f.Close()
	defer os.Remove(f.Name())
	return sshG("sshr-import-defaults.invalid", f.Name())
}

// ImportItem is one alias of the ssh config and what happened to it
type ImportItem struct {
	Alias string
	Host  *Host
	// Skipped says why the alias was not added, empty when it was
	Skipped string
	Notes   []string
}

// ImportSSHConfig adds the hosts of the user's ssh config that sshr does
// not have yet, a host whose name or address, user and port are saved
// already is skipped, dryRun only reports
func (s *Store) ImportSSHConfig(dryRun bool) ([]ImportItem, error) {
	aliases, err := SSHConfigAliases()
	if err != nil {
		return nil, err
	}
	defaults, err := sshDefaults()
	if err != nil {
		return nil, err
	}
	existing, err := s.List()
	if err != nil {
		return nil, err
	}
	var out []ImportItem
	for _, alias := range aliases {
		item := ImportItem{Alias: alias}
		g, err := sshG(alias, sshConfigFile)
		if err != nil {
			item.Skipped = err.Error()
			out = append(out, item)
			continue
		}
		h, notes := hostFromSSHConfig(alias, g, defaults)
		item.Notes = notes
		for _, e := range existing {
			if strings.EqualFold(e.Name, h.Name) {
				item.Skipped = "a host with this name is saved already"
			} else if e.Host == h.Host && e.User == h.User && e.Port == h.Port {
				item.Skipped = "saved already as " + e.Name
			}
		}
		if item.Skipped == "" {
			if dryRun {
				item.Host = &h
			} else if saved, err := s.Add(h); err != nil {
				item.Skipped = err.Error()
			} else {
				item.Host = saved
				existing = append(existing, *saved)
			}
		}
		out = append(out, item)
	}
	return out, nil
}
