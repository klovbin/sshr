package sshcmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"sshr.dev/internal/hosts"
	"sshr.dev/internal/settings"
)

// ErrHardwareKeyRequired means the host may connect only with a key on a
// FIDO token and its login is something else
var ErrHardwareKeyRequired = errors.New("this host needs a key on a hardware token")

// hardwareKeyArgs keep ssh to keys on a token: only sk key types, no
// password, no keyboard-interactive, no Kerberos, no host-based login, no
// connection of another run shared through ControlMaster, the command line
// wins over ssh_config, ssh uses the first value it gets
var hardwareKeyArgs = []string{
	"-o", "IdentitiesOnly=yes",
	"-o", "PubkeyAcceptedKeyTypes=sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
	"-o", "PreferredAuthentications=publickey",
	"-o", "PasswordAuthentication=no",
	"-o", "KbdInteractiveAuthentication=no",
	"-o", "GSSAPIAuthentication=no",
	"-o", "HostbasedAuthentication=no",
	"-o", "ControlMaster=no",
	"-o", "ControlPath=none",
}

// hardwareKeyRequired tells whether the settings ask for a token key for
// h, a settings file that does not parse asks for one on every host when
// it names hardware_key at all, a broken file must not drop the
// requirement for sshr mcp, sshr serve and the tunnels, which do not say
// that they connect without settings, a file without it asks for none
func hardwareKeyRequired(h *Host) bool {
	st, err := LoadSettings()
	if err == nil {
		return st.HardwareKeyRequired(h.ID)
	}
	path, perr := settings.Path()
	if perr != nil {
		return false
	}
	raw, rerr := os.ReadFile(path)
	return rerr == nil && bytes.Contains(raw, []byte(`"hardware_key`))
}

// hardwareKeyEverywhere tells whether every host needs a token key, a
// host that is not saved included, the jump hops of an unsaved spec then
// go through sshr so the rule applies to them
func hardwareKeyEverywhere() bool {
	return hardwareKeyRequired(&Host{})
}

// CheckHardwareKey refuses a host under the requirement whose login is
// not a key on a token: a password of any kind, a key kept in sshr,
// 1Password or Bitwarden, the default keys of ssh, a key file or an agent
// key of another type
func CheckHardwareKey(h *Host) error {
	refuse := func(why string) error {
		return fmt.Errorf("%w: %s %s, give it the handle of a key made with sshr key new --sk (sshr edit %s -k <file>)", ErrHardwareKeyRequired, h.Name, why, h.Name)
	}
	if h.PasswordMode != "" {
		return refuse("logs in with a password")
	}
	switch h.KeyMode {
	case KeyVault, KeyOnePassword, KeyBitwarden:
		return refuse("keeps a software key in sshr, 1Password or Bitwarden")
	case KeyAgent:
		if !strings.HasPrefix(pubKeyType(h.KeyPub), "sk-") {
			return refuse("takes a key of the agent that is not on a token or not chosen")
		}
		return nil
	}
	if h.Key == "" {
		return refuse("uses the default keys of ssh")
	}
	if hosts.HardwareKeyFile(ExpandHome(h.Key)) == "" {
		return refuse("has a key file that is not on a token")
	}
	return nil
}

// pubKeyType is the type of a public key line, empty when it does not read
func pubKeyType(line string) string {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return ""
	}
	return pub.Type()
}
