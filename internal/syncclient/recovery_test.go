package syncclient

import (
	"strings"
	"testing"
	"time"
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
