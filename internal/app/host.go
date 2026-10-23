package app

import "golang.org/x/crypto/ssh"

// Password modes of a host, an empty mode means no password at all, the
// key file, ssh-agent or ssh config decide
const (
	// PasswordSaved keeps the password sealed with the vault key in the
	// host file, sshr hands it to ssh
	PasswordSaved = "saved"
	// PasswordAsk stores nothing, ssh asks on the terminal every time
	PasswordAsk = "ask"
)

// KeyVault is the KeyMode of a host whose private key is stored sealed in
// its host file instead of a key file on disk
const KeyVault = "vault"

// KeyAgent is the KeyMode of a host whose key stays in an ssh agent, the
// system one, the 1Password SSH agent or any agent socket, sshr only tells
// ssh which agent and which of its keys to use
const KeyAgent = "agent"

// AgentOnePassword names the 1Password SSH agent in Host.Agent
const AgentOnePassword = "1password"

// Modes for hosts whose secrets live in 1Password, read with the op CLI on
// every connect and never kept on this machine
const (
	PasswordOnePassword = "1password"
	KeyOnePassword      = "1password"
)

// Modes for hosts whose secrets live in Bitwarden, read with the bw CLI on
// every connect, the reference is the item ID (or a name that finds one
// item)
const (
	PasswordBitwarden = "bitwarden"
	KeyBitwarden      = "bitwarden"
)

// Dest is the user@host argument for ssh.
func (h *Host) Dest() string {
	if h.User == "" {
		return h.Host
	}
	return h.User + "@" + h.Host
}

// KeyFingerprint is the SHA256 fingerprint of a vault key, as ssh-keygen -l
// shows it, empty when the host has none
func (h *Host) KeyFingerprint() string {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(h.KeyPub))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(pub)
}

// agentKey tells whether the key of h is served by an agent of sshr, a
// key sealed in sshr or one read from 1Password
func (h *Host) agentKey() bool {
	return h.KeyMode == KeyVault || h.KeyMode == KeyOnePassword || h.KeyMode == KeyBitwarden
}

// PasswordFromSshr tells whether sshr hands the password to ssh, from the
// vault or from 1Password
func (h *Host) PasswordFromSshr() bool {
	return h.Key == "" && (h.PasswordMode == PasswordSaved || h.PasswordMode == PasswordOnePassword || h.PasswordMode == PasswordBitwarden)
}

// Via is the jump spec the connection goes through: Jump, or the Gateway
// once ConnectArgs found the host down directly, empty for a direct one
func (h *Host) Via() string {
	if h.Jump != "" {
		return h.Jump
	}
	return h.route
}

// RouteViaGateway makes the connection go through the Gateway when on,
// directly when off, the route is never anything but the saved Gateway
func (h *Host) RouteViaGateway(on bool) {
	h.route = ""
	if on {
		h.route = h.Gateway
	}
}
