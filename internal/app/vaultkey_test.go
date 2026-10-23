package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func testKey(t *testing.T, passphrase string) (pemData []byte, pub string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "t")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "t", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	return pem.EncodeToMemory(block), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

func TestVaultKeySealed(t *testing.T) {
	useMockKeychain(t)
	s := &Store{Dir: t.TempDir()}
	data, pub := testKey(t, "")
	h, err := s.Add(Host{Host: "h", User: "u", KeyData: data, Password: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if h.KeyMode != KeyVault || h.PasswordMode != "" || h.KeyPub != pub {
		t.Fatalf("host = %+v", h)
	}
	b, _ := os.ReadFile(filepath.Join(s.Dir, h.ID+".json"))
	if strings.Contains(string(b), "PRIVATE KEY") || !strings.Contains(string(b), `"key_sealed": "v2:`) {
		t.Fatalf("host file:\n%s", b)
	}
	if p, _ := os.ReadFile(s.pubPath(h)); strings.TrimSpace(string(p)) != pub {
		t.Errorf("pub file = %q", p)
	}
	// editing without pasting the key again keeps it
	if _, err := s.Update(h.ID, Host{Name: "n2", Host: "h", User: "u", KeyMode: KeyVault}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Find(h.ID)
	if got.KeySealed == "" || got.KeyPub != pub {
		t.Errorf("key lost on edit: %+v", got)
	}
	args := strings.Join(s.vaultKeyArgs(got), " ")
	if !strings.Contains(args, "IdentitiesOnly=yes") || !strings.Contains(args, "IdentityAgent=SSH_AUTH_SOCK") {
		t.Errorf("vaultKeyArgs = %q", args)
	}
	if _, err := s.Add(Host{Host: "h", User: "u", KeyMode: KeyVault}); !errors.Is(err, ErrKeyRequired) {
		t.Errorf("vault mode with no key: %v", err)
	}
	if _, err := s.Add(Host{Host: "h", User: "u", KeyData: []byte(pub)}); err == nil {
		t.Error("a public key was accepted as a private key")
	}
	if err := s.Delete(h.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.pubPath(h)); !os.IsNotExist(err) {
		t.Errorf("pub file left after delete: %v", err)
	}
}

func TestVaultKeyPassphrase(t *testing.T) {
	useMockKeychain(t)
	s := &Store{Dir: t.TempDir()}
	data, pub := testKey(t, "pp")
	if _, err := s.Add(Host{Host: "h", User: "u", KeyData: data}); !errors.Is(err, ErrKeyPassphrase) {
		t.Fatalf("no passphrase: %v", err)
	}
	if _, err := s.Add(Host{Host: "h", User: "u", KeyData: data, KeyPassphrase: "bad"}); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	h, err := s.Add(Host{Host: "h", User: "u", KeyData: data, KeyPassphrase: "pp"})
	if err != nil || h.KeyPub != pub {
		t.Fatalf("with passphrase: %+v, %v", h, err)
	}
}

func TestVaultKeyAgent(t *testing.T) {
	useMockKeychain(t)
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv("SSH_AUTH_SOCK", "/user/agent")
	s := &Store{Dir: t.TempDir()}
	data, pub := testKey(t, "")
	h, err := s.Add(Host{Host: "h", User: "u", KeyData: data})
	if err != nil {
		t.Fatal(err)
	}
	h, _ = s.Find(h.ID)
	cmd := exec.Command("true")
	stop, err := AttachAuth(cmd, h)
	if err != nil {
		t.Fatal(err)
	}
	sock := ""
	for _, kv := range cmd.Env {
		if v, ok := strings.CutPrefix(kv, "SSH_AUTH_SOCK="); ok {
			sock = v
		}
	}
	c, err := dialAgent(sock)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := agent.NewClient(c).List()
	c.Close()
	if err != nil || len(keys) != 1 || strings.TrimSpace(string(ssh.MarshalAuthorizedKey(keys[0]))) != pub {
		t.Fatalf("agent keys = %v, %v", keys, err)
	}
	// a jump hop gets the user's agent back
	env := strings.Join(StripAuthEnv(cmd.Env), "\n")
	if !strings.Contains(env, "SSH_AUTH_SOCK=/user/agent") || strings.Contains(env, sock) {
		t.Errorf("hop env:\n%s", env)
	}
	stop()
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("agent socket left: %v", err)
	}
}

// a stored key is sealed for its destination: an address changed in the
// file by hand does not open it, a change through sshr keeps it, an old v1
// seal is sealed again (#174)
func TestStoredKeyBoundToDestination(t *testing.T) {
	useMockKeychain(t)
	s := &Store{Dir: t.TempDir()}
	data, _ := testKey(t, "")
	h, err := s.Add(Host{Name: "k", Host: "10.0.0.1", User: "u", KeyData: data})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.Dir, h.ID+".json")
	b, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(b), `"10.0.0.1"`, `"203.0.113.66"`, 1)), 0o600)
	moved, _ := s.Find(h.ID)
	if _, err := loadKey(moved); err == nil {
		t.Fatal("the key opened for an address changed outside sshr")
	}
	os.WriteFile(path, b, 0o600)
	cur, _ := s.Find(h.ID)
	cur.Host, cur.Port = "10.0.0.2", 2222
	if _, err := s.Update(h.ID, *cur); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Find(h.ID)
	if _, err := loadKey(got); err != nil {
		t.Fatalf("after an edit in sshr: %v", err)
	}
	// a key sealed the old way is opened and sealed for its destination
	old, err := seal(data, h.ID, "key")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(path)
	var m map[string]any
	json.Unmarshal(b, &m)
	m["key_sealed"] = old
	b, _ = json.Marshal(m)
	os.WriteFile(path, b, 0o600)
	s.upgradeSeals()
	b, _ = os.ReadFile(path)
	if !strings.Contains(string(b), `"key_sealed": "v2:`) {
		t.Fatalf("the v1 key seal was not upgraded:\n%s", b)
	}
	up, _ := s.Find(h.ID)
	if _, err := loadKey(up); err != nil {
		t.Fatalf("the upgraded key does not open: %v", err)
	}
}

// a host moved by another device does not take the key stored here to its
// new address, the key is dropped and a note says so (#177)
func TestImportedMoveDoesNotTakeTheStoredKey(t *testing.T) {
	useMockKeychain(t)
	s := &Store{Dir: t.TempDir()}
	data, _ := testKey(t, "")
	h, err := s.Add(Host{Name: "k", Host: "10.0.0.1", User: "u", KeyData: data})
	if err != nil {
		t.Fatal(err)
	}
	in := *h
	in.KeySealed, in.Host = "", "203.0.113.66"
	_, notes := FromOtherDevice(in, h)
	got, err := s.Import(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeySealed != "" {
		t.Fatalf("the stored key went with the host: %q", got.KeySealed)
	}
	if _, err := loadKey(got); err == nil {
		t.Fatal("the key opens for the address the other device chose")
	}
	found := false
	for _, n := range notes {
		found = found || strings.Contains(n, "key stored here is not used")
	}
	if !found {
		t.Errorf("no note: %q", notes)
	}
	// the same host from another device without a move keeps the key
	h2, err := s.Add(Host{Name: "k2", Host: "10.0.0.2", User: "u", KeyData: data})
	if err != nil {
		t.Fatal(err)
	}
	same := *h2
	same.KeySealed, same.Tags = "", []string{"x"}
	kept, err := s.Import(same)
	if err != nil || kept.KeySealed == "" {
		t.Fatalf("an import without a move lost the key: %v", err)
	}
	if _, err := loadKey(kept); err != nil {
		t.Fatalf("the kept key does not open: %v", err)
	}
}
