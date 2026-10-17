package app

import (
	"encoding/json"
	"errors"
	"fmt"
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

// opTimeout bounds one op call, long enough for the 1Password app to ask
// for a fingerprint or the account password
const opTimeout = 2 * time.Minute

// opBin is the op executable, tests point it at a fake
var opBin = "op"

// opCLI is the 1Password CLI, op asks the app for a fingerprint or the
// account password, the timeout leaves time for that
var opCLI = managerCLI{name: "1Password", bin: &opBin, missing: ErrNoOP,
	url: "https://developer.1password.com/docs/cli/get-started/", timeout: opTimeout,
	stuck: "1Password did not answer in time, is the app locked?"}

// opRun runs op with stdin and returns its output
func opRun(stdin []byte, args ...string) ([]byte, error) { return opCLI.run(stdin, args...) }

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
