package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Modes for hosts whose secrets live in 1Password, read with the op CLI on
// every connect and never kept on this machine
const (
	PasswordOnePassword = "1password"
	KeyOnePassword      = "1password"
)

// ErrNoOP means the 1Password CLI (op) is not installed
var ErrNoOP = errors.New("no_op")

// ErrOPIntegrationOff means Settings → Developer → Integrate with 1Password CLI is off
var ErrOPIntegrationOff = errors.New("op_integration_off")

// ErrOPPrivacy means macOS is blocking this app from 1Password shared data
// (System Settings → Privacy & Security → Files and Folders → Data shared by 1Password).
// See https://developer.1password.com/docs/cli/app-integration/ (macOS 27 note).
var ErrOPPrivacy = errors.New("op_privacy")

// OPAccount is one account from `op account list` (desktop app integration).
type OPAccount struct {
	URL         string `json:"url"`
	Email       string `json:"email"`
	UserUUID    string `json:"user_uuid"`
	AccountUUID string `json:"account_uuid"`
}

// Ref is what --account / OP_ACCOUNT accept: email, user ID or sign-in address (op docs).
func (a OPAccount) Ref() string {
	switch {
	case a.Email != "":
		return a.Email
	case a.UserUUID != "":
		return a.UserUUID
	case a.AccountUUID != "":
		return a.AccountUUID
	default:
		return a.URL
	}
}

// Label is the account name shown in settings (email, else Ref).
func (a OPAccount) Label() string {
	if a.Email != "" {
		return a.Email
	}
	return a.Ref()
}

// opDevelopersURL is Settings > Developer in the 1Password app.
const opDevelopersURL = "onepassword://settings/developers"

// opCLIInstallURL is where to get the `op` binary when LookPath fails.
const opCLIInstallURL = "https://developer.1password.com/docs/cli/get-started/"

// opTimeout bounds one op call, long enough for the 1Password app to ask
// for a fingerprint or the account password
const opTimeout = 2 * time.Minute

// opBin is the op executable, tests point it at a fake
var opBin = "op"

// opCLI is the 1Password CLI, op asks the app for a fingerprint or the
// account password, the timeout leaves time for that
var opCLI = managerCLI{
	name: "1Password", bin: &opBin, missing: ErrNoOP,
	url: opCLIInstallURL, timeout: opTimeout,
	stuck:   "1Password did not answer in time, is the app locked?",
	resolve: resolveOpBin,
	env:     opEnv,
	errMsg:  opErrMessage,
}

// opRun runs op with stdin and returns its output
func opRun(stdin []byte, args ...string) ([]byte, error) { return opCLI.run(stdin, args...) }

func openURL(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("cmd", "/c", "start", "", url).Start()
	default:
		if err := exec.Command("xdg-open", url).Start(); err == nil {
			return nil
		}
		return fmt.Errorf("%w: cannot open %s", ErrNoOP, url)
	}
}

// OpenURL opens url in the default browser.
func OpenURL(url string) error { return openURL(url) }

// OpenOnePasswordCLIIntegration opens the Developer settings page.
func OpenOnePasswordCLIIntegration() error {
	return openURL(opDevelopersURL)
}

// OpenOnePasswordCLIInstall opens the install docs for the `op` CLI.
func OpenOnePasswordCLIInstall() error {
	return openURL(opCLIInstallURL)
}

// ListOPAccounts lists accounts added to the 1Password desktop app
// (`op account list` — https://developer.1password.com/docs/cli/use-multiple-accounts/).
func ListOPAccounts() ([]OPAccount, error) {
	out, err := opRun(nil, "account", "list", "--format=json")
	if err != nil {
		return nil, mapOPErr(err)
	}
	out = bytes.TrimSpace(out)
	if len(out) == 0 || bytes.Equal(out, []byte("null")) {
		return nil, privacyOrEmpty()
	}
	var accounts []OPAccount
	if err := json.Unmarshal(out, &accounts); err != nil {
		return nil, fmt.Errorf("1Password: bad account list: %v", err)
	}
	if len(accounts) == 0 {
		return nil, privacyOrEmpty()
	}
	return accounts, nil
}

func privacyOrEmpty() error {
	if runtime.GOOS == "darwin" {
		return fmt.Errorf("%w: allow sshr under System Settings → Privacy & Security → Files and Folders → Data shared by 1Password", ErrOPPrivacy)
	}
	return errors.New("1Password: no accounts in the desktop app")
}

// AuthorizeOPAccount runs `op vault list --account` so 1Password shows the
// biometric CLI prompt for this process (doc: any command after app integration).
func AuthorizeOPAccount(account string) error {
	account = strings.TrimSpace(account)
	if account == "" {
		return errors.New("1Password account is empty")
	}
	_, err := opRun(nil, "vault", "list", "--account", account, "--format=json")
	return mapOPErr(err)
}

// OpenOPPrivacySettings opens macOS Files and Folders privacy (for Data shared by 1Password).
func OpenOPPrivacySettings() error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	return exec.Command("open", "x-apple.systempreferences:com.apple.preference.security?Privacy_FilesAndFolders").Start()
}

func mapOPErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrNoOP) || errors.Is(err, ErrOPPrivacy) || errors.Is(err, ErrOPIntegrationOff) {
		return err
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "no accounts configured") ||
		strings.Contains(msg, "data shared by 1password") {
		return fmt.Errorf("%w: %v", ErrOPPrivacy, err)
	}
	if strings.Contains(msg, "cli is not enabled") {
		return fmt.Errorf("%w: %v", ErrOPIntegrationOff, err)
	}
	if strings.Contains(msg, "connecting to desktop app") ||
		strings.Contains(msg, "desktop app not running") ||
		strings.Contains(msg, "lostconnectiontoapp") ||
		strings.Contains(msg, "connectionreset") {
		if runtime.GOOS == "darwin" {
			return fmt.Errorf("%w: %v", ErrOPPrivacy, err)
		}
		return fmt.Errorf("%w: %v", ErrOPIntegrationOff, err)
	}
	return err
}

// opPathCandidates covers brew / usr installs when a .app has a short PATH.
var opPathCandidates = []string{
	"/opt/homebrew/bin/op",
	"/usr/local/bin/op",
}

func resolveOpBin() (string, error) {
	if opBin != "op" {
		return exec.LookPath(opBin)
	}
	// Use a properly signed op only (Team ID 2BUA8C4S2C). An ad-hoc copy
	// next to sshr.app cannot talk to the desktop app over XPC.
	if bin, err := exec.LookPath(opBin); err == nil {
		return bin, nil
	}
	for _, p := range opPathCandidates {
		if fileExists(p) {
			return p, nil
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		for _, p := range []string{
			home + "/.local/bin/op",
			home + "/bin/op",
		} {
			if fileExists(p) {
				return p, nil
			}
		}
		if p := findGrokBotOp(home); p != "" {
			return p, nil
		}
	}
	return "", fmt.Errorf("%w: the 1Password CLI (op) is not installed, see %s", ErrNoOP, opCLIInstallURL)
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// findGrokBotOp picks the newest ~/.grokbot/onepassword-cli/<ver>/<arch>/op.
func findGrokBotOp(home string) string {
	root := filepath.Join(home, ".grokbot", "onepassword-cli")
	ents, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	arch := runtime.GOARCH
	var bestVer, bestPath string
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(root, e.Name(), arch, "op")
		if !fileExists(p) {
			continue
		}
		if bestVer == "" || e.Name() > bestVer {
			bestVer, bestPath = e.Name(), p
		}
	}
	return bestPath
}

// opErrMessage picks the useful line from op stderr. op often appends
// Connect-server help after the real error — that must not become the message.
func opErrMessage(stderr string) string {
	var first string
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		low := strings.ToLower(line)
		if strings.Contains(low, "op_connect_host") ||
			strings.Contains(low, "connect server") ||
			strings.Contains(low, "learn more:") ||
			strings.HasPrefix(line, "- ") {
			continue
		}
		if i := strings.Index(line, "] "); i >= 0 && strings.Contains(line[:i+1], "ERROR") {
			line = strings.TrimSpace(line[i+2:])
			if j := strings.Index(line, " "); j >= 0 && strings.Contains(line[:j], "/") {
				if k := strings.Index(line[j+1:], " "); k >= 0 {
					line = strings.TrimSpace(line[j+1+k+1:])
				}
			}
		}
		if first == "" {
			first = line
		}
	}
	return first
}

// opEnv keeps the process env (needed for 1Password IPC on macOS), forces
// biometric app integration, and strips Connect / service-account overrides.
func opEnv(args []string) []string {
	listing := len(args) >= 2 && args[0] == "account" && args[1] == "list"
	var out []string
	for _, e := range os.Environ() {
		key, _, _ := strings.Cut(e, "=")
		switch key {
		case "OP_CONNECT_HOST", "OP_CONNECT_TOKEN", "OP_SERVICE_ACCOUNT_TOKEN",
			"OP_BIOMETRIC_UNLOCK_ENABLED":
			continue
		case "OP_ACCOUNT":
			if listing {
				continue
			}
		}
		out = append(out, e)
	}
	out = append(out, "OP_BIOMETRIC_UNLOCK_ENABLED=true")
	if home, err := os.UserHomeDir(); err == nil {
		out = append(out, "HOME="+home)
	}
	if !listing {
		if st, err := LoadSettings(); err == nil && st.OPAccount != "" {
			out = append(out, "OP_ACCOUNT="+st.OPAccount)
		}
	}
	return out
}

// checkOPRef refuses anything that is not an op:// secret reference
func checkOPRef(ref string) error {
	rest, ok := strings.CutPrefix(ref, "op://")
	if !ok || strings.Count(rest, "/") < 2 {
		return fmt.Errorf("%q is not a 1Password secret reference, expected op://vault/item/field", ref)
	}
	return nil
}

// opRead reads one field by its secret reference
func opRead(ref string) ([]byte, error) {
	return opRun(nil, "read", "--no-newline", ref)
}

// opReadKey reads the private key of an SSH Key item in OpenSSH format,
// op gives PKCS#8 by default
func opReadKey(ref string) ([]byte, error) {
	if !strings.Contains(ref, "?") {
		ref += "?ssh-format=openssh"
	}
	return opRead(ref)
}

// opKeyPub reads the key of an SSH Key item once and returns its public
// half, kept with the host for ssh -i and to show which key it is
func opKeyPub(ref string) (string, error) {
	plain, err := opReadKey(ref)
	if err != nil {
		return "", err
	}
	return publicKeyOf(plain, ref)
}

// opStorePassword creates a 1Password item for a password typed with
// PasswordOnePassword and keeps only its reference, the password itself is
// not written to the host file
func (s *Store) opStorePassword(h *Host) error {
	if h.PasswordMode != PasswordOnePassword || h.Password == "" {
		return nil
	}
	if h.PasswordRef != "" {
		return errors.New("the host is linked to a 1Password item, change the password there and leave it empty here")
	}
	vault := ""
	if s.OPVault != nil {
		vault = *s.OPVault
	} else if st, err := LoadSettings(); err == nil {
		vault = st.OPVault
	}
	// the password goes in a JSON template on stdin, op warns that
	// assignments in argv are visible to other processes
	type field struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Purpose string `json:"purpose"`
		Label   string `json:"label"`
		Value   string `json:"value"`
	}
	tmpl, err := json.Marshal(struct {
		Title    string   `json:"title"`
		Category string   `json:"category"`
		Tags     []string `json:"tags"`
		Fields   []field  `json:"fields"`
	}{
		Title:    "sshr " + h.Name,
		Category: "LOGIN",
		Tags:     []string{"sshr"},
		Fields: []field{
			{ID: "username", Type: "STRING", Purpose: "USERNAME", Label: "username", Value: h.User},
			{ID: "password", Type: "CONCEALED", Purpose: "PASSWORD", Label: "password", Value: h.Password},
		},
	})
	if err != nil {
		return err
	}
	args := []string{"item", "create", "--format", "json"}
	if vault != "" {
		args = append(args, "--vault", vault)
	}
	out, err := opRun(tmpl, append(args, "-")...)
	if err != nil {
		return err
	}
	var item struct {
		ID    string `json:"id"`
		Vault struct {
			ID string `json:"id"`
		} `json:"vault"`
		Fields []struct {
			Purpose   string `json:"purpose"`
			Reference string `json:"reference"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(out, &item); err != nil {
		return fmt.Errorf("1Password: unexpected answer to item create: %v", err)
	}
	ref := ""
	for _, f := range item.Fields {
		if f.Purpose == "PASSWORD" {
			ref = f.Reference
		}
	}
	if ref == "" {
		if item.ID == "" || item.Vault.ID == "" {
			return errors.New("1Password created the item but did not say where")
		}
		ref = "op://" + item.Vault.ID + "/" + item.ID + "/password"
	}
	h.PasswordRef, h.Password = ref, ""
	return nil
}
