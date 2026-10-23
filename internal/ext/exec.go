package ext

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"sshr.dev/internal/app"
)

// secretEnv are the variables that hold or open a secret of sshr or of a
// password manager sshr talks to, an extension never gets them: ssh asks
// through them for a password, bw and op unlock a vault with them
var secretEnv = []string{
	"SSH_ASKPASS", "SSH_ASKPASS_REQUIRE",
	"BW_SESSION", "BW_PASSWORD", "BW_CLIENTID", "BW_CLIENTSECRET",
	"OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_TOKEN", "OP_CONNECT_HOST",
}

// secretEnvPrefixes cover the families: one OP_SESSION_ variable per
// 1Password account, SSHR_ are the internal ones of a running sshr (the
// askpass socket and token, the sync keys)
var secretEnvPrefixes = []string{"OP_SESSION_", "SSHR_"}

// Env returns the environment of an extension: the one of the caller
// without the secrets above and with what sshr tells an extension, the
// protocol, the kind it was started for, its folder and the sshr binary to
// call back (sshr list --json), the folder it may write to, names are compared in upper case because
// Windows spells them either way, inside a hop of sshr SSH_AUTH_SOCK is the
// private agent of a key kept in sshr, app.StripAuthEnv puts the user's own
// back first
func Env(parent []string, kind, dir, data, sshrBin string) []string {
	return append(cleanEnv(parent),
		"SSHR_EXT_PROTOCOL="+strconv.Itoa(Protocol),
		"SSHR_EXT_KIND="+kind,
		"SSHR_EXT_DIR="+dir,
		"SSHR_EXT_DATA="+data,
		"SSHR_BIN="+sshrBin,
		// the files of the extension are pinned, a byte code cache written
		// into the folder would stop the next run
		"PYTHONDONTWRITEBYTECODE=1",
	)
}

// cleanEnv is parent without the secrets above and with the user's own
// agent, also what git is started with to fetch an extension
func cleanEnv(parent []string) []string {
	parent = app.StripAuthEnv(parent)
	out := make([]string, 0, len(parent)+4)
	for _, kv := range parent {
		name, _, _ := strings.Cut(kv, "=")
		if isSecretEnv(strings.ToUpper(name)) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func isSecretEnv(name string) bool {
	for _, s := range secretEnv {
		if name == s {
			return true
		}
	}
	for _, p := range secretEnvPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Command checks the files of the extension against the install and returns
// the command to run for kind with args, the caller connects its input and
// output, the program is the file of the folder by its full path, nothing
// is looked up in PATH and no shell is involved
func (i *Installed) Command(kind string, args []string, sshrBin string) (*exec.Cmd, error) {
	if !i.Has(kind) {
		return nil, fmt.Errorf("extension %s does not do %q, it has %s", i.Name, kind, strings.Join(i.Kinds, ", "))
	}
	if err := i.Verify(); err != nil {
		return nil, err
	}
	// the manifest in i was read before the files were checked, what runs
	// must be the one that was checked
	data, err := os.ReadFile(filepath.Join(i.Dir, ManifestFile))
	if err != nil {
		return nil, fmt.Errorf("extension %s: %v", i.Name, err)
	}
	if checked, err := ParseManifest(data); err != nil || !reflect.DeepEqual(checked, i.Manifest) {
		return nil, fmt.Errorf("%w: the manifest of extension %s is not the one that was checked, install it again to trust it", ErrChanged, i.Name)
	}
	argv, err := i.Argv(runtime.GOOS)
	if err != nil {
		return nil, err
	}
	program := filepath.Join(i.Dir, filepath.FromSlash(argv[0]))
	info, err := os.Stat(program)
	if err != nil {
		return nil, fmt.Errorf("extension %s: %v", i.Name, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("extension %s: %s is not a file", i.Name, argv[0])
	}
	if runtime.GOOS != "windows" && info.Mode()&0o111 == 0 {
		return nil, fmt.Errorf("extension %s: %s is not executable, fix it in the extension and install it again", i.Name, argv[0])
	}
	if err := os.MkdirAll(i.Data, 0o700); err != nil {
		return nil, fmt.Errorf("extension %s: %v", i.Name, err)
	}
	cmd := exec.Command(program, append(argv[1:], args...)...)
	cmd.Env = Env(os.Environ(), kind, i.Dir, i.Data, sshrBin)
	return cmd, nil
}
