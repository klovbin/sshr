package syncclient

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sshr.dev/internal/hosts"
	"sshr.dev/internal/syncproto"
	"sshr.dev/internal/vault"
)

// The recovery kit (#150) is the seed of a device listed in the account
// as Recovery, printed on paper, the rules of syncproto.CheckPrimary let it
// only claim the account and, after the wait, hand it to one new device,
// key rotations deliver new vault keys to it like to any device

const anchorPrefix = "recovery-"

// anchorID is the entry that holds the anchor of the kit device id, a
// fresh machine restoring the kit opens it to know the account is the real
// one and not one a hostile server made up with a vault key it chose
func anchorID(device string) string { return anchorPrefix + short(device, 16) }

func isAnchor(id string) bool { return strings.HasPrefix(id, anchorPrefix) }

// anchorPayload is what the anchor entry holds, a value only the seed of
// the kit gives
func anchorPayload(seed []byte) []byte {
	b, _ := json.Marshal(map[string]string{"recovery_anchor": hex.EncodeToString(derive(seed, "recovery anchor", 32))})
	return b
}

// DefaultRecoveryWait is the wait between a claim of the kit and the
// hand-over when the primary picks none
const DefaultRecoveryWait = 7 * 24 * time.Hour

// RecoveryKit is a printed kit: Header in plain text (the account and
// where it lives) and Secret, the groups to copy by hand
type RecoveryKit struct {
	Header, Secret string
}

// CreateRecoveryKit makes a new recovery kit on the primary device, a kit
// made before is replaced (its device is removed, the vault key changes),
// pass wraps the secret part when not empty, wait is the time a claim of
// the kit waits before the hand-over, the owner's devices cancel in it
func (c *Client) CreateRecoveryKit(pass string, wait time.Duration) (out *RecoveryKit, err error) {
	err = c.run(func() error {
		out, err = c.createRecoveryKit(pass, wait)
		return err
	})
	return out, err
}

func (c *Client) createRecoveryKit(pass string, wait time.Duration) (*RecoveryKit, error) {
	if wait > syncproto.MaxRecoveryWait*time.Second {
		return nil, errors.New("the wait of a recovery kit is at most a year")
	}
	if wait < syncproto.MinRecoveryWait*time.Second {
		return nil, fmt.Errorf("the wait of a recovery kit is at least %s, the owner's devices need time to cancel a claim", time.Duration(syncproto.MinRecoveryWait)*time.Second)
	}
	if err := c.Pull(); err != nil {
		return nil, err
	}
	if err := c.errNotPrimary("makes a recovery kit"); err != nil {
		return nil, err
	}
	if err := c.claimPrimary(); err != nil {
		return nil, err
	}
	if old := c.st.Recovery; old != "" {
		if _, err := c.removeDevice(old); err != nil {
			return nil, fmt.Errorf("replacing the recovery kit: %v", err)
		}
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	keys, err := newDeviceKeys(seed)
	if err != nil {
		return nil, err
	}
	dev := keys.device("recovery kit " + time.Now().Format("2006-01-02"))
	body, _ := json.Marshal(syncproto.NewAccountRequest{Device: dev})
	b, err := c.backend().Join(body)
	if err != nil {
		return nil, err
	}
	var tr syncproto.TokenResponse
	if err := json.Unmarshal(b, &tr); err != nil {
		return nil, err
	}
	err = c.push(func() (pushPlan, error) {
		if c.st.Recovery == dev.ID {
			return pushPlan{}, nil
		}
		if err := c.errNotPrimary("makes a recovery kit"); err != nil {
			return pushPlan{}, err
		}
		return pushPlan{
			devices:  append(append([]syncproto.Device(nil), c.st.Trusted...), dev),
			recovery: &recoveryFields{device: dev.ID, wait: int64(wait / time.Second)},
			anchorID: anchorID(dev.ID), anchorPlain: anchorPayload(seed),
		}, nil
	})
	if err != nil {
		// the kit device waits for approval on the server, it would take a
		// place there and could be approved by mistake
		c.backend().RemoveDevice(dev.ID)
		return nil, err
	}
	key, err := c.vaultKey(c.st.Epoch)
	if err != nil {
		return nil, err
	}
	if err := c.putEnvelope(dev, c.st.Epoch, key); err != nil {
		return nil, err
	}
	if err := c.backend().Activate(dev.ID); err != nil {
		return nil, err
	}
	secret, err := encodeKit(recoveryKit{Seed: seed, Token: tr.Token, Floor: c.st.Counter}, pass)
	if err != nil {
		return nil, err
	}
	return &RecoveryKit{Header: c.kitHeader(dev, pass != ""), Secret: secret}, nil
}

// kitHeader is the plain part of a kit: what the account is and where it
// lives, never a credential of the store
func (c *Client) kitHeader(dev syncproto.Device, pass bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "sshr sync recovery kit, made %s\n", time.Now().Format("2006-01-02"))
	fmt.Fprintf(&b, "account   %s\n", c.st.Account)
	if c.st.Backend != nil {
		cfg, _ := json.Marshal(c.st.Backend.Config)
		fmt.Fprintf(&b, "store     %s %s (its secret is not on this paper, have it ready)\n", c.st.Backend.Kind, cfg)
	} else {
		fmt.Fprintf(&b, "server    %s\n", c.st.Server)
	}
	fmt.Fprintf(&b, "device    %s\n", DeviceFingerprint(dev))
	if pass {
		b.WriteString("passphrase needed, it is not on this paper\n")
	}
	fmt.Fprintf(&b, "wait      %s from a claim to the hand-over\n", (time.Duration(c.st.RecoveryWait) * time.Second).Round(time.Hour))
	return b.String()
}

// CancelRecovery removes the device of the recovery kit on the primary
// device, a claim made with it is cancelled, the vault key changes, the
// paper is worth nothing after it, a new kit is made with
// CreateRecoveryKit
func (c *Client) CancelRecovery() error {
	return c.run(func() error {
		if err := c.Pull(); err != nil {
			return err
		}
		if c.st.Recovery == "" {
			return errors.New("this account has no recovery kit")
		}
		_, err := c.removeDevice(c.st.Recovery)
		return err
	})
}

// recoveryClient is the client of the kit device during a restore: its own
// folder next to the state of this machine and its own keychain names,
// no hosts, every entry carried on
func (c *Client) recoveryClient() *Client {
	dir := filepath.Join(c.Dir, "recovery")
	return &Client{
		Store: &hosts.Store{Dir: filepath.Join(dir, "hosts")}, Dir: dir, KeyPrefix: c.prefix() + "recovery-",
		Log: c.Log, HTTP: c.HTTP, Now: c.Now, Backend: c.Backend, BackendRef: c.BackendRef,
		StoreSecret: c.StoreSecret, OpenBackend: c.OpenBackend, kit: true,
	}
}

// RestoreClaim starts bringing the account back to this machine from a
// recovery kit: it checks the kit against the account (the anchor only the
// seed opens, the counter printed on it), the kit device claims the
// account and this machine asks to join, ready is when RestoreFinish may
// hand the account over, the owner's devices warn and can cancel until
// then, account is from the header of the kit, server too unless the
// client has a store set up for it
func (c *Client) RestoreClaim(server, account, kitText, name string, pass func() (string, error)) (ready time.Time, err error) {
	if err := c.CheckFree(); err != nil {
		return time.Time{}, err
	}
	k, err := decodeKit(kitText, pass)
	if err != nil {
		return time.Time{}, err
	}
	rc := c.recoveryClient()
	if _, err := os.Stat(rc.statePath()); err == nil {
		return time.Time{}, errors.New("a restore is under way on this machine, finish it with sshr sync recovery restore --finish")
	}
	if err := os.MkdirAll(rc.Store.Dir, 0o700); err != nil {
		return time.Time{}, err
	}
	srv, err := c.serverOf(server)
	if err != nil {
		return time.Time{}, err
	}
	if err := vault.SecretSet(rc.prefix()+"device", k.Seed); err != nil {
		return time.Time{}, err
	}
	if rc.keys, err = newDeviceKeys(k.Seed); err != nil {
		return time.Time{}, err
	}
	self := rc.keys.device("")
	rc.st = &state{Server: srv, Account: strings.TrimSpace(account), DeviceID: self.ID, Token: k.Token, Name: "recovery kit", Entries: map[string]entryState{}, Skipped: map[string]syncproto.Entry{}}
	rc.keepBackend()
	if err := rc.bootstrap(k); err != nil {
		rc.forget()
		return time.Time{}, err
	}
	if err := rc.saveNew(); err != nil {
		rc.forget()
		return time.Time{}, err
	}
	if rc.st.Claim == 0 {
		err = rc.run(func() error {
			if err := rc.load(); err != nil {
				return err
			}
			return rc.push(func() (pushPlan, error) {
				if rc.st.Claim != 0 {
					return pushPlan{}, nil
				}
				return pushPlan{recovery: &recoveryFields{device: rc.st.Recovery, wait: rc.st.RecoveryWait, claim: rc.st.Counter + 1}}, nil
			})
		})
		if err != nil {
			rc.forget()
			return time.Time{}, fmt.Errorf("the kit could not claim the account, run the restore again: %v", err)
		}
	} else {
		rc.logf("the account was claimed with this kit already on change %d", rc.st.Claim)
	}
	if err := rc.run(func() error {
		if err := rc.load(); err != nil {
			return err
		}
		rc.st.ClaimSeen, rc.st.ClaimSeenAt = rc.st.Claim, rc.now()
		return rc.save()
	}); err != nil {
		return time.Time{}, err
	}
	code := rc.st.Account + "." + strings.ReplaceAll(Fingerprint(self.SignPub), "-", "")
	if _, err := c.Join(server, code, name); err != nil {
		// a new restore finds the claim made and goes on from it
		rc.forget()
		return time.Time{}, fmt.Errorf("the account is claimed, this machine could not ask to join, run the restore again: %v", err)
	}
	return rc.now().Add(time.Duration(rc.st.RecoveryWait) * time.Second), nil
}

// bootstrap reads the head of the account as the kit device sees it on a
// fresh machine: no history before, so the account is checked by what
// only the real one has, the anchor entry the seed opens, and by the
// counter printed on the kit
func (c *Client) bootstrap(k recoveryKit) error {
	_, raw, err := c.backend().Head()
	if err != nil {
		return fmt.Errorf("reading the account: %v", err)
	}
	var sm syncproto.Signed
	var m syncproto.Manifest
	if err := json.Unmarshal(raw, &sm); err != nil {
		return err
	}
	if err := json.Unmarshal(sm.Body, &m); err != nil {
		return err
	}
	switch {
	case m.Account != c.st.Account:
		return errors.New("the store holds another account than the one on the kit")
	case m.Counter < k.Floor:
		return fmt.Errorf("the account is at change %d, older than the kit (%d), the server shows an old state, this kit is not used against it", m.Counter, k.Floor)
	case m.Version < 2 || m.Recovery != c.st.DeviceID:
		return errors.New("this kit was replaced or cancelled, its device is no longer the recovery kit of the account")
	}
	if err := checkFormat(m.Version); err != nil {
		return err
	}
	if err := verifySignature(&sm, m.Devices); err != nil {
		return err
	}
	key, err := c.envelopeKey(m.Epoch)
	if err != nil {
		return fmt.Errorf("the vault key for the kit: %v", err)
	}
	if err := verifyMAC(&sm, key); err != nil {
		return err
	}
	e, ok := m.Entries[anchorID(c.st.DeviceID)]
	if !ok {
		return errors.New("the account has no anchor of this kit, it is not the account the kit was made for")
	}
	plain, err := c.fetchBlob(anchorID(c.st.DeviceID), e.Hash, key, m.Epoch)
	if err != nil || subtle.ConstantTimeCompare(plain, anchorPayload(k.Seed)) != 1 {
		return errors.New("the anchor of the kit does not match, this is not the account the kit was made for")
	}
	if err := vault.SecretSet(c.prefix()+"key-"+fmt.Sprint(m.Epoch), key); err != nil {
		return err
	}
	c.st.Counter, c.st.Head, c.st.Trusted, c.st.Epoch = m.Counter, syncproto.BodyHash(sm.Body), m.Devices, m.Epoch
	c.st.Primary, c.st.Format, c.st.Recovery, c.st.RecoveryWait, c.st.Claim = m.Primary, m.Version, m.Recovery, m.RecoveryWait, m.Claim
	for id, e := range m.Entries {
		c.st.Skipped[id] = e
	}
	return nil
}

// forget drops what a restore cut short left of the kit device here
func (c *Client) forget() {
	if c.st != nil {
		vault.SecretDelete(c.prefix() + "key-" + fmt.Sprint(c.st.Epoch))
	}
	vault.SecretDelete(c.prefix() + "device")
	vault.SecretDelete(c.storeSecretName())
	os.RemoveAll(c.Dir)
}

// RestoreFinish hands the account to this machine once the wait of the
// claim is over: the kit device adds it as the primary device, this
// machine takes the hosts, removes the kit device (the vault key changes)
// and forgets the kit, a new kit is made with CreateRecoveryKit
func (c *Client) RestoreFinish() error {
	rc := c.recoveryClient()
	if _, err := os.Stat(rc.statePath()); err != nil {
		return errors.New("no restore is under way on this machine, start one with sshr sync recovery restore")
	}
	if err := c.load(); err != nil {
		return err
	}
	// the keys of this machine, not the record the server lists for it, a
	// server that swapped the encryption key would get the vault key
	self := c.self()
	me := self.ID
	c.st = nil
	err := rc.run(func() error {
		if err := rc.pull(); err != nil {
			return fmt.Errorf("the kit device cannot read the account, the claim was probably cancelled on the primary device: %v", err)
		}
		if left := rc.st.ClaimSeenAt.Add(time.Duration(rc.st.RecoveryWait) * time.Second).Sub(rc.now()); left > 0 {
			return fmt.Errorf("the account can be handed over in %s", left.Round(time.Minute))
		}
		b, err := rc.backend().Devices()
		if err != nil {
			return err
		}
		var recs []syncproto.DeviceRecord
		if err := json.Unmarshal(b, &recs); err != nil {
			return err
		}
		listed := false
		for i := range recs {
			listed = listed || recs[i].ID == me
		}
		if !listed {
			return errors.New("the join request of this machine is gone from the account, start again")
		}
		dev := &self
		if err := rc.push(func() (pushPlan, error) {
			if rc.st.Primary == me {
				return pushPlan{}, nil
			}
			return pushPlan{
				devices:  append(append([]syncproto.Device(nil), rc.st.Trusted...), *dev),
				primary:  me,
				recovery: &recoveryFields{device: rc.st.Recovery, wait: rc.st.RecoveryWait},
			}, nil
		}); err != nil {
			return err
		}
		key, err := rc.vaultKey(rc.st.Epoch)
		if err != nil {
			return err
		}
		if err := rc.putEnvelope(*dev, rc.st.Epoch, key); err != nil {
			return err
		}
		return rc.backend().Activate(me)
	})
	if err != nil {
		return err
	}
	if err := c.Pull(); err != nil {
		return fmt.Errorf("the account is handed to this machine but its first sync failed, run sshr sync: %v", err)
	}
	if err := c.CancelRecovery(); err != nil {
		return fmt.Errorf("this machine is the primary device now, the old kit device is still in the account, run sshr sync recovery cancel: %v", err)
	}
	rc.st = nil
	rc.Leave(true)
	os.RemoveAll(rc.Dir)
	return nil
}
