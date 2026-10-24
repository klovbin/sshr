package app

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// CopyArgs builds the scp command line that copies files to h (send) or
// from it, with the same key, agent, password, jump hosts and shared
// connection as ssh, scp takes the port as -P, -p there keeps file times,
// -r is always given, so folders copy too, legacy uses the old scp
// protocol (-O), which needs no SFTP subsystem on the server
func (e sshEnv) CopyArgs(h *Host, send, legacy bool, sources []string, dest string) ([]string, error) {
	if len(sources) == 0 {
		return nil, errors.New("nothing to copy")
	}
	conn, err := e.ConnectArgs(h)
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, len(conn)+len(sources)+6)
	// scp starts ssh itself, it must be the ssh sshr chose (#313)
	if ssh := childSSH(runtime.GOOS, SSHPath, os.Getenv("SSHR_SSH"), false); ssh != "" {
		args = append(args, "-S", ssh)
	}
	for i := 0; i < len(conn); i++ {
		if conn[i] == "-p" && i+1 < len(conn) {
			args = append(args, "-P", conn[i+1])
			i++
			continue
		}
		args = append(args, conn[i])
	}
	if legacy {
		args = append(args, "-O")
	}
	args = append(args, "-r", "--")
	if send {
		for _, src := range sources {
			args = append(args, localSpec(src))
		}
		return append(args, remoteSpec(h, dest)), nil
	}
	for _, src := range sources {
		args = append(args, remoteSpec(h, src))
	}
	return append(args, localSpec(dest)), nil
}

// localSpec keeps scp from reading a local path as host:path, scp takes a
// colon before the first slash for a host, ./ in front of a relative path
// puts a slash first, absolute paths are left as they are, a Windows
// drive letter included
func localSpec(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	seps := "/"
	if filepath.Separator == '\\' {
		seps = `/\`
	}
	if i := strings.IndexByte(path, ':'); i >= 0 && !strings.ContainsAny(path[:i], seps) {
		return "./" + path
	}
	return path
}

// remoteSpec is [user@]host:path for scp, an IPv6 address goes in brackets
// so its colons are not read as the path separator, unless it was saved in
// them already, an empty path is the home folder
func remoteSpec(h *Host, path string) string {
	host := h.Host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	if h.User != "" {
		host = h.User + "@" + host
	}
	return host + ":" + path
}
