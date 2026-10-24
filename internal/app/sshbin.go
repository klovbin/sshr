package app

import (
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
)

// The ssh sshr runs (#154): the first one on PATH, except on Windows where
// the ssh of Git for Windows (msys) often comes first, it does not read
// Windows paths in ProxyCommand or IdentityFile the way the rest of sshr
// writes them, the OpenSSH of Windows is taken instead when it is there

// SSHPath is the ssh binary sshr runs, looked up on every call, PATH may
// change in a long running process and the lookup is cheap
func SSHPath() (string, error) {
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
	case err == nil && !isMsysSSH(found):
		return found, nil
	case system != "" && exists(system):
		return system, nil
	case err == nil:
		return found, nil
	}
	return "", errors.New("ssh not found, install the OpenSSH client of Windows (Settings, Optional features)")
}

// isMsysSSH tells the ssh of Git for Windows or MSYS2 by its place, it sits
// in a usr\bin folder of their tree
func isMsysSSH(path string) bool {
	p := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	return strings.Contains(p, `\usr\bin\`) && (strings.Contains(p, `\git\`) || strings.Contains(p, `\msys`))
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

// sshVersion runs path -V once per path, ok is false when it does not say
// an OpenSSH version
func sshVersion(path string) (major, minor int, ok bool) {
	if v, hit := sshVersions.Load(path); hit {
		r := v.([3]int)
		return r[0], r[1], r[2] == 1
	}
	out, _ := exec.Command(path, "-V").CombinedOutput()
	major, minor, ok = parseSSHVersion(string(out))
	okInt := 0
	if ok {
		okInt = 1
	}
	sshVersions.Store(path, [3]int{major, minor, okInt})
	return major, minor, ok
}

// askpassSupported tells whether the ssh at path takes a saved password
// from sshr: SSH_ASKPASS_REQUIRE came with OpenSSH 8.4, an older ssh asks
// on the terminal instead, an ssh whose version is unknown is let through
func askpassSupported(path string) error {
	major, minor, ok := sshVersion(path)
	if !ok || major > 8 || major == 8 && minor >= 4 {
		return nil
	}
	return fmt.Errorf("%s is OpenSSH %d.%d, a password saved in sshr needs OpenSSH 8.4 or newer, update ssh or log in with a key", path, major, minor)
}
