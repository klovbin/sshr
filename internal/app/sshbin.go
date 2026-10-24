package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The ssh sshr runs (#154): the first one on PATH, except on Windows where
// the ssh of Git for Windows (msys) often comes first, it does not read
// Windows paths in ProxyCommand or IdentityFile the way the rest of sshr
// writes them, the OpenSSH of Windows is taken instead when it is there

// SSHPath is the ssh binary sshr runs, looked up on every call, PATH may
// change in a long running process and the lookup is cheap
func SSHPath() (string, error) {
	if own := os.Getenv("SSHR_SSH"); own != "" {
		// the user names the ssh, the msys one of Git included (its agent,
		// its config), nothing is picked instead
		if !fileExists(own) {
			return "", fmt.Errorf("SSHR_SSH names %s, there is no such file", own)
		}
		return own, nil
	}
	return pickSSH(runtime.GOOS, exec.LookPath, os.Getenv("SystemRoot"), fileExists)
}

// sshCommand is exec.Command for the ssh of SSHPath, a missing ssh runs
// "ssh" and fails the way it did before, with ssh's own error
func sshCommand(args ...string) *exec.Cmd {
	path, err := SSHPath()
	if err != nil {
		path = "ssh"
	}
	return exec.Command(path, args...)
}

// SSHCommand is sshCommand for the front ends
func SSHCommand(args ...string) *exec.Cmd { return sshCommand(args...) }

// childSSH is the ssh a program that starts ssh itself (scp, mosh) is told
// to use: the one SSHR_SSH names on any system, on Windows the one SSHPath
// chose, otherwise "" since their own PATH lookup finds the same, mosh
// splits --ssh on spaces, a path with spaces is not passed to it
func childSSH(goos string, path func() (string, error), own string, mosh bool) string {
	if own == "" && goos != "windows" {
		return ""
	}
	p, err := path()
	if err != nil || mosh && strings.ContainsAny(p, " \t") {
		return ""
	}
	return p
}

// SCPPath is the scp to run, on Windows the one next to the chosen ssh, so
// both come from the same OpenSSH
func SCPPath() (string, error) {
	if runtime.GOOS == "windows" {
		if ssh, err := SSHPath(); err == nil {
			if scp := filepath.Join(filepath.Dir(ssh), "scp.exe"); fileExists(scp) {
				return scp, nil
			}
		}
	}
	p, err := exec.LookPath("scp")
	if err != nil {
		return "", errors.New("scp not found in PATH, it comes with OpenSSH")
	}
	return p, nil
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// pickSSH chooses the ssh, the lookups come in so a test can stand in for
// a Windows machine
func pickSSH(goos string, look func(string) (string, error), systemRoot string, exists func(string) bool) (string, error) {
	found, err := look("ssh")
	if goos != "windows" {
		if err != nil {
			return "", errors.New("ssh not found in PATH")
		}
		return found, nil
	}
	system := ""
	if systemRoot != "" {
		system = filepath.Join(systemRoot, "System32", "OpenSSH", "ssh.exe")
	}
	switch {
	case err == nil && !isMsysSSH(found, exists):
		return found, nil
	case system != "" && exists(system):
		return system, nil
	case err == nil:
		return found, nil
	}
	return "", errors.New("ssh not found, install the OpenSSH client of Windows (Settings, Optional features)")
}

// isMsysSSH tells the ssh of Git for Windows, MSYS2 or Cygwin by the
// runtime next to it (msys-2.0.dll, cygwin1.dll), PortableGit and custom
// folders included, a scoop or chocolatey shim is a separate small program
// and is taken as it is, SSHR_SSH names the real one when that matters
func isMsysSSH(path string, exists func(string) bool) bool {
	// a Windows path, cut by hand so the test reads it on any system
	i := strings.LastIndexAny(path, `\/`)
	if i < 0 {
		return false
	}
	dir := path[:i+1]
	return exists(dir+"msys-2.0.dll") || exists(dir+"cygwin1.dll")
}

var sshVersionRe = regexp.MustCompile(`OpenSSH(?:_for_Windows)?_(\d+)\.(\d+)`)

// parseSSHVersion reads the version from what ssh -V prints, ok is false
// for an ssh that is not OpenSSH
func parseSSHVersion(out string) (major, minor int, ok bool) {
	m := sshVersionRe.FindStringSubmatch(out)
	if m == nil {
		return 0, 0, false
	}
	major, _ = strconv.Atoi(m[1])
	minor, _ = strconv.Atoi(m[2])
	return major, minor, true
}

var sshVersions sync.Map

// sshVersionTimeout bounds ssh -V, a wrapper that hangs or a slow first
// scan must not hold the connect, a timeout counts as an unknown version
const sshVersionTimeout = 3 * time.Second

// sshVersionOf is how askpassSupported reads a version, tests stand in for
// it so they do not depend on the ssh of the machine
var sshVersionOf = sshVersion

// sshVersion runs path -V once per path, size and time of the file, an
// ssh updated in place is read again, ok is false when it does not say an
// OpenSSH version
func sshVersion(path string) (major, minor int, ok bool) {
	key := path
	if fi, err := os.Stat(path); err == nil {
		key = fmt.Sprintf("%s|%d|%d", path, fi.Size(), fi.ModTime().UnixNano())
	}
	if v, hit := sshVersions.Load(key); hit {
		r := v.([3]int)
		return r[0], r[1], r[2] == 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), sshVersionTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "-V")
	// a child of a wrapper keeps the output open after the wrapper is
	// killed, the wait stops shortly after the kill anyway
	cmd.WaitDelay = 500 * time.Millisecond
	out, _ := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return 0, 0, false
	}
	major, minor, ok = parseSSHVersion(string(out))
	okInt := 0
	if ok {
		okInt = 1
	}
	sshVersions.Store(key, [3]int{major, minor, okInt})
	return major, minor, ok
}

// askpassSupported tells whether the ssh at path takes a saved password
// from sshr: SSH_ASKPASS_REQUIRE came with OpenSSH 8.4, an older ssh asks
// on the terminal instead, an ssh whose version is unknown is let through
func askpassSupported(path string) error {
	major, minor, ok := sshVersionOf(path)
	if !ok || major > 8 || major == 8 && minor >= 4 {
		return nil
	}
	return fmt.Errorf("%s is OpenSSH %d.%d, a password saved in sshr needs OpenSSH 8.4 or newer, update ssh or log in with a key", path, major, minor)
}
