package sshcmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"sshr.dev/internal/settings"
)

// CertTarget binds a host listed for certificates to where it points, a
// host repointed on another device keeps its ID and loses the certificate
func CertTarget(h *Host) string {
	sum := sha256.Sum256([]byte(destination(*h)))
	return hex.EncodeToString(sum[:16])
}

// certFor returns the principals of h when it logs in with a certificate,
// a settings file that does not read but names certificates refuses the
// login, it never falls back to another way in
func certFor(h *Host) ([]string, bool, error) {
	st, err := LoadSettings()
	if err != nil {
		path, perr := settings.Path()
		if perr != nil {
			return nil, false, nil
		}
		raw, rerr := os.ReadFile(path)
		switch {
		case rerr != nil && !os.IsNotExist(rerr):
			return nil, false, fmt.Errorf("settings.json does not read (%v), it may list hosts for certificates, fix it first", err)
		case rerr == nil && bytes.Contains(raw, []byte(`"cert_hosts"`)):
			return nil, false, fmt.Errorf("settings.json does not read (%v) and lists hosts for certificates, fix it first", err)
		}
		return nil, false, nil
	}
	return st.CertFor(h.ID, CertTarget(h))
}

// certArgs are the ssh options of a login with a certificate: only the
// certificate in the file AttachAuth writes, with its key from the agent
// of this process, no password, no other key, no agent forwarding
func certArgs(h *Host) ([]string, error) {
	dir, err := ControlDir()
	if err != nil {
		return nil, err
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	if err := checkConfigIdentities(h); err != nil {
		return nil, err
	}
	sweepCertFiles(dir, time.Now())
	h.SetCertFile(filepath.Join(dir, "cert-"+hex.EncodeToString(b[:])+".pub"))
	return []string{
		"-i", h.CertFile(),
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=SSH_AUTH_SOCK",
		"-o", "ForwardAgent=no",
		"-o", "PreferredAuthentications=publickey",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		// a shared connection logged in some other way, or one that
		// outlives the certificate, is not used
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		"-p", strconv.Itoa(h.Port),
	}, nil
}

// checkConfigIdentities refuses a host the ssh config of the user gives
// key or certificate files, ssh offers them next to the certificate and
// a server that takes one would let the login in without it, -i and
// IdentityFile none do not take them away, the files ssh picks without a
// config are its defaults and ssh skips those once -i names a file
func checkConfigIdentities(h *Host) error {
	sshBin, err := SSHPath()
	if err != nil {
		return err
	}
	dest := []string{"-p", strconv.Itoa(h.Port), "-l", h.User, "--", h.Host}
	own := dest
	if sshUserConfig != "" {
		own = append([]string{"-F", sshUserConfig}, dest...)
	}
	withConfig, err := sshConfigFiles(sshBin, own)
	if err != nil {
		return err
	}
	defaults, err := sshConfigFiles(sshBin, append([]string{"-F", os.DevNull}, dest...))
	if err != nil {
		return err
	}
	var extra []string
	for _, f := range withConfig {
		if !slices.Contains(defaults, f) {
			extra = append(extra, f)
		}
	}
	if len(extra) > 0 {
		return fmt.Errorf("%s logs in with a certificate, but the ssh config gives it %s, ssh would offer them too, take them out of the config for this host or turn the certificate off with sshr cert off %s", h.Name, strings.Join(extra, ", "), h.Name)
	}
	return nil
}

// sshUserConfig is the ssh config a test reads in place of the one ssh
// finds in the home of the passwd entry
var sshUserConfig string

// sshConfigFiles lists the identity and certificate files ssh -G picks
// for the destination
func sshConfigFiles(sshBin string, args []string) ([]string, error) {
	out, err := exec.Command(sshBin, append([]string{"-G"}, args...)...).Output()
	if err != nil {
		return nil, fmt.Errorf("ssh -G: %v", err)
	}
	var files []string
	for _, line := range strings.Split(string(out), "\n") {
		key, val, _ := strings.Cut(strings.TrimSpace(line), " ")
		if (key == "identityfile" || key == "certificatefile") && val != "none" {
			files = append(files, key+" "+val)
		}
	}
	return files, nil
}

// attachCert signs a certificate for a key made for this one login and
// serves both from an agent of this process, the key never leaves memory,
// the certificate file goes when ssh ends
func attachCert(cmd *exec.Cmd, h *Host) (func(), error) {
	noop := func() {}
	principals, ok, err := certFor(h)
	if err != nil {
		return noop, err
	}
	if !ok {
		return noop, fmt.Errorf("%s is no longer listed for certificates, connect again", h.Name)
	}
	ca, err := LoadCertCA()
	if err != nil {
		return noop, err
	}
	st, _ := LoadSettings()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return noop, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return noop, err
	}
	machine, _ := os.Hostname()
	cert, err := ca.SignUserCert(sshPub, "sshr "+machine+" "+h.Name, principals, st.CertMinutes(), time.Now())
	if err != nil {
		return noop, err
	}
	// the path of this login, a later ConnectArgs on the same host sets
	// another, O_EXCL: the name is new for this login, a file there is not
	// ours
	path := h.CertFile()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return noop, err
	}
	_, werr := f.Write(ssh.MarshalAuthorizedKey(cert))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	remove := func() { os.Remove(path) }
	if werr != nil {
		remove()
		return noop, werr
	}
	keys := agent.NewKeyring()
	if err := keys.Add(agent.AddedKey{PrivateKey: priv, Certificate: cert, Comment: h.Name}); err != nil {
		remove()
		return noop, err
	}
	stop, err := serveAgent(cmd, keys, h.Name)
	if err != nil {
		remove()
		return noop, err
	}
	if err := logCert(h, cert); err != nil {
		fmt.Fprintf(os.Stderr, "sshr: the certificate is not in the log (%v), its serial is %d\n", err, cert.Serial)
	}
	return func() { stop(); remove() }, nil
}

// certFileAge is how long a certificate file of a login may stay, ssh
// reads it once when it starts, a file older than this is from an sshr
// that was killed before it could remove it
const certFileAge = time.Hour

// sweepCertFiles removes the certificate files of logins that ended
// without their sshr, they hold only public data
func sweepCertFiles(dir string, now time.Time) {
	names, _ := filepath.Glob(filepath.Join(dir, "cert-*.pub"))
	for _, n := range names {
		if fi, err := os.Lstat(n); err == nil && fi.Mode().IsRegular() && now.Sub(fi.ModTime()) > certFileAge {
			os.Remove(n)
		}
	}
}

// certLogMax is the size at which the log of signed certificates moves to
// a .old file and starts again
const certLogMax = 1 << 20

// certLogPath is ~/.sshr/cert-log.jsonl
func certLogPath() (string, error) {
	p, err := settings.Path()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(p), "cert-log.jsonl"), nil
}

// logCert appends a line on the signed certificate to the log, its serial
// is what a revocation list on a server names
func logCert(h *Host, cert *ssh.Certificate) error {
	path, err := certLogPath()
	if err != nil {
		return err
	}
	if fi, err := os.Stat(path); err == nil && fi.Size() > certLogMax {
		os.Rename(path, path+".old")
	}
	line, err := json.Marshal(struct {
		Time        time.Time `json:"time"`
		Host        string    `json:"host"`
		Name        string    `json:"name"`
		Principals  []string  `json:"principals"`
		Serial      uint64    `json:"serial"`
		KeyID       string    `json:"key_id"`
		ValidBefore time.Time `json:"valid_before"`
	}{time.Now().UTC(), h.ID, h.Name, cert.ValidPrincipals, cert.Serial, cert.KeyId, time.Unix(int64(cert.ValidBefore), 0).UTC()})
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(append(line, '\n'))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}
