package syncclient

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"sshr.dev/internal/syncproto"
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
	fmt.Fprintf(&b, "device    %s\n", Fingerprint(dev.SignPub))
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
