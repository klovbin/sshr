package syncclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sshr.dev/internal/syncserver"
)

// TestCreateRecoveryKit checks that the primary device makes a kit: its
// device joins the account as Recovery, the anchor entry is carried by
// every device without a word, a second kit replaces the first (the vault
// key changes), cancel takes the kit out, a device that is not primary
// makes none (#150)
func TestCreateRecoveryKit(t *testing.T) {
	w := newWorld(t)
	web, _ := w.pair()
	if _, err := w.b.CreateRecoveryKit("", DefaultRecoveryWait); err == nil || !strings.Contains(err.Error(), "only the primary device") {
		t.Fatalf("b made a kit: %v", err)
	}
	if _, err := w.a.CreateRecoveryKit("", time.Hour); err == nil {
		t.Fatal("a kit with a wait under a day")
	}
	kit, err := w.a.CreateRecoveryKit("pw", DefaultRecoveryWait)
	must(t, err)
	if !strings.Contains(kit.Header, w.a.st.Account) || !strings.Contains(kit.Header, "passphrase needed") {
		t.Fatalf("header:\n%s", kit.Header)
	}
	k, err := decodeKit(kit.Secret, func() (string, error) { return "pw", nil })
	must(t, err)
	keys, err := newDeviceKeys(k.Seed)
	must(t, err)
	rid := keys.device("").ID
	if w.a.st.Recovery != rid || len(w.a.st.Trusted) != 3 || k.Floor != w.a.st.Counter {
		t.Fatalf("recovery %q (kit %q), %d devices, floor %d at %d", w.a.st.Recovery, rid, len(w.a.st.Trusted), k.Floor, w.a.st.Counter)
	}
	must(t, w.b.Pull())
	if w.b.st.Recovery != rid {
		t.Fatalf("b sees recovery %q", w.b.st.Recovery)
	}
	if _, ok := w.b.st.Skipped[anchorID(rid)]; !ok || strings.Contains(w.log.String(), "skipped") {
		t.Fatalf("anchor on b: %v\n%s", w.b.st.Skipped, w.log.String())
	}
	if _, err := w.b.Store.Find(web.ID); err != nil {
		t.Fatal(err)
	}
	must(t, w.b.Push())

	epoch := w.a.st.Epoch
	kit2, err := w.a.CreateRecoveryKit("", DefaultRecoveryWait)
	must(t, err)
	k2, err := decodeKit(kit2.Secret, noPass)
	must(t, err)
	keys2, err := newDeviceKeys(k2.Seed)
	must(t, err)
	if w.a.st.Recovery != keys2.device("").ID || w.a.st.Epoch != epoch+1 || len(w.a.st.Trusted) != 3 {
		t.Fatalf("after a second kit: recovery %q, epoch %d, %d devices", w.a.st.Recovery, w.a.st.Epoch, len(w.a.st.Trusted))
	}
	if _, ok := w.a.st.Skipped[anchorID(rid)]; ok {
		t.Fatal("the anchor of the old kit stayed")
	}
	must(t, w.b.Pull())

	must(t, w.a.CancelRecovery())
	must(t, w.b.Pull())
	if w.b.st.Recovery != "" || len(w.b.st.Trusted) != 2 {
		t.Fatalf("after cancel b sees recovery %q, %d devices", w.b.st.Recovery, len(w.b.st.Trusted))
	}
}

// TestRestoreFromKit checks a restore on a fresh machine (#150): the kit
// claims the account, the hand-over waits, the owner's devices warn, after
// the wait the new machine gets the hosts and is the primary device, the
// kit device is out and the paper is worth nothing
func TestRestoreFromKit(t *testing.T) {
	w := newWorld(t)
	web, _ := w.pair()
	clock := time.Now()
	now := func() time.Time { return clock }
	w.srv.Config.Handler.(*syncserver.Server).Now = now
	kit, err := w.a.CreateRecoveryKit("pw", DefaultRecoveryWait)
	must(t, err)
	must(t, w.b.Pull())
	w.b.Now = now

	n := w.client("n-")
	n.Now = now
	pass := func() (string, error) { return "pw", nil }
	if _, err := n.RestoreClaim(w.srv.URL, w.a.st.Account, kit.Secret, "new laptop", func() (string, error) { return "wrong", nil }); err == nil {
		t.Fatal("a wrong passphrase went through")
	}
	ready, err := n.RestoreClaim(w.srv.URL, w.a.st.Account, kit.Secret, "new laptop", pass)
	must(t, err)
	if ready.Sub(clock) != DefaultRecoveryWait {
		t.Fatalf("ready in %s", ready.Sub(clock))
	}
	must(t, w.b.Pull())
	if !strings.Contains(w.log.String(), "recovery kit of this account was used") {
		t.Fatalf("b did not warn:\n%s", w.log.String())
	}
	if err := n.RestoreFinish(); err == nil || !strings.Contains(err.Error(), "handed over in") {
		t.Fatalf("finish before the wait: %v", err)
	}
	clock = clock.Add(DefaultRecoveryWait + time.Hour)
	must(t, n.RestoreFinish())
	if n.st == nil {
		must(t, n.load())
	}
	if n.st.Primary != n.st.DeviceID || n.st.Recovery != "" {
		t.Fatalf("on n: primary %q (n %q), recovery %q", n.st.Primary, n.st.DeviceID, n.st.Recovery)
	}
	if _, err := n.Store.Find(web.ID); err != nil {
		t.Fatalf("n has no hosts: %v", err)
	}
	must(t, w.b.Pull())
	if w.b.st.Primary != n.st.DeviceID {
		t.Fatalf("b sees primary %q", w.b.st.Primary)
	}
	if _, err := os.Stat(filepath.Join(n.Dir, "recovery")); !os.IsNotExist(err) {
		t.Fatalf("the kit device is still on n: %v", err)
	}
	// the paper is worth nothing now
	m := w.client("m-")
	if _, err := m.RestoreClaim(w.srv.URL, w.a.st.Account, kit.Secret, "thief", pass); err == nil {
		t.Fatal("a used kit claimed the account again")
	}
}

// TestRestoreCancelled checks that the primary device cancels a claim and
// the restore then fails
func TestRestoreCancelled(t *testing.T) {
	w := newWorld(t)
	w.pair()
	clock := time.Now()
	now := func() time.Time { return clock }
	w.srv.Config.Handler.(*syncserver.Server).Now = now
	kit, err := w.a.CreateRecoveryKit("", DefaultRecoveryWait)
	must(t, err)
	n := w.client("n-")
	n.Now = now
	_, err = n.RestoreClaim(w.srv.URL, w.a.st.Account, kit.Secret, "thief", noPass)
	must(t, err)
	w.a.Now = now
	must(t, w.a.CancelRecovery())
	clock = clock.Add(DefaultRecoveryWait + time.Hour)
	if err := n.RestoreFinish(); err == nil {
		t.Fatal("a cancelled claim finished")
	}
	must(t, w.b.Pull())
	if w.b.st.Primary != w.a.st.DeviceID {
		t.Fatalf("primary moved to %q", w.b.st.Primary)
	}
}
