package sshcmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"sshr.dev/internal/fileio"
	"sshr.dev/internal/settings"
	"sshr.dev/internal/vault"
)

// The kinds of a certificate authority of this machine
const (
	// CASoftware keeps the private key of the authority sealed with the
	// vault key in a local file, whoever opens the vault can log in
	// wherever the authority is trusted
	CASoftware = "software"
	// CAToken keeps it on a FIDO token, every certificate needs a touch
	CAToken = "sk"
)

// ErrNoCA means no certificate authority is set up on this machine
var ErrNoCA = errors.New("no certificate authority is set up here, sshr cert ca init makes one")

// CertCA is the certificate authority of this machine, cert-ca.json next
// to settings.json, it never syncs
type CertCA struct {
	Type string `json:"type"`
	// Pub is the public key in authorized_keys form, the line a server
	// trusts
	Pub string `json:"pub"`
	// Sealed is the private key of a software authority, sealed with the
	// vault key
	Sealed string `json:"sealed,omitempty"`
	// Handle is the key file of an authority on a token
	Handle string `json:"handle,omitempty"`
}

// certCAPath is ~/.sshr/cert-ca.json
func certCAPath() (string, error) {
	p, err := settings.Path()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(p), "cert-ca.json"), nil
}

// LoadCertCA reads the authority of this machine, ErrNoCA when there is
// none
func LoadCertCA() (*CertCA, error) {
	path, err := certCAPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, ErrNoCA
	}
	if err != nil {
		return nil, err
	}
	var ca CertCA
	if err := json.Unmarshal(b, &ca); err != nil {
		return nil, fmt.Errorf("%s is damaged: %v", path, err)
	}
	if ca.Type != CASoftware && ca.Type != CAToken {
		return nil, fmt.Errorf("%s holds an authority of kind %q, a kind of a newer sshr, update sshr", path, ca.Type)
	}
	if _, err := ca.PublicKey(); err != nil {
		return nil, fmt.Errorf("%s is damaged: %v", path, err)
	}
	return &ca, nil
}

// InitSoftwareCA makes a software authority, an authority that is there
// stays unless replace, the servers that trust it would all need the new
// key
func InitSoftwareCA(replace bool) (*CertCA, error) {
	path, err := certCAPath()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err == nil && !replace {
		return nil, errors.New("a certificate authority is set up here already, the servers trust its key, replace it with --replace")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "sshr certificate authority")
	if err != nil {
		return nil, err
	}
	sealed, err := vault.Seal(pem.EncodeToMemory(block), "cert-ca", "key")
	if err != nil {
		return nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	ca := &CertCA{Type: CASoftware, Pub: authorizedLine(sshPub, "sshr-ca"), Sealed: sealed}
	b, err := json.MarshalIndent(ca, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := fileio.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		return nil, err
	}
	return ca, nil
}

// PublicKey is the key servers trust
func (ca *CertCA) PublicKey() (ssh.PublicKey, error) {
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ca.Pub))
	return k, err
}

// SignUserCert signs a user certificate for pub that holds for minutes
// from now, it starts five minutes back so a server clock a little behind
// takes it, keyID names the login in the server log, only a pty and port
// forwards are allowed, agent and X11 forwarding are not
func (ca *CertCA) SignUserCert(pub ssh.PublicKey, keyID string, principals []string, minutes int, now time.Time) (*ssh.Certificate, error) {
	if ca.Type != CASoftware {
		return nil, fmt.Errorf("an authority of kind %q does not sign in this sshr yet", ca.Type)
	}
	if len(principals) == 0 {
		return nil, errors.New("a certificate needs a principal")
	}
	signer, err := ca.softwareSigner()
	if err != nil {
		return nil, err
	}
	var serial [8]byte
	if _, err := rand.Read(serial[:]); err != nil {
		return nil, err
	}
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          binary.BigEndian.Uint64(serial[:]),
		CertType:        ssh.UserCert,
		KeyId:           keyID,
		ValidPrincipals: principals,
		ValidAfter:      uint64(now.Add(-5 * time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(time.Duration(minutes) * time.Minute).Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{
			"permit-pty":             "",
			"permit-port-forwarding": "",
		}},
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, err
	}
	return cert, nil
}

func (ca *CertCA) softwareSigner() (ssh.Signer, error) {
	plain, err := vault.Unseal(ca.Sealed, "cert-ca", "key")
	if errors.Is(err, vault.ErrSealBroken) {
		return nil, errors.New("the key of the certificate authority does not open with the vault key of this machine (keychain reset or the file copied from another machine), make a new one with sshr cert ca init --replace")
	}
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(plain)
	if err != nil {
		return nil, err
	}
	// a file edited by hand would show servers a key nothing signs with
	pub, err := ca.PublicKey()
	if err != nil || !bytes.Equal(pub.Marshal(), signer.PublicKey().Marshal()) {
		return nil, errors.New("the key of the certificate authority does not match the key cert-ca.json shows, the file was changed, make a new one with sshr cert ca init --replace")
	}
	return signer, nil
}

// authorizedLine is pub as one authorized_keys line with comment
func authorizedLine(pub ssh.PublicKey, comment string) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + comment
}
