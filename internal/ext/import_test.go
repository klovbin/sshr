package ext

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestParseImportReadsOnlyTheListedFields(t *testing.T) {
	in := `{"hosts":[
	  {"key":"putty:web","name":"web","host":"10.0.0.5","port":2222,"user":"deploy","key_file":"/home/u/.ssh/id","jump":"gw","session":"tmux","tags":["Prod","eu"],"forwards":["db -L 5432:localhost:5432"],
	   "password":"hunter2","key_data":"-----BEGIN","password_ref":"op://x"}]}`
	hosts, warnings, err := ParseImport([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].Key != "putty:web" || hosts[0].Port != 2222 || hosts[0].KeyFile != "/home/u/.ssh/id" {
		t.Fatalf("hosts %+v", hosts)
	}
	got := strings.Join(warnings, "\n")
	for _, field := range []string{`"password"`, `"key_data"`, `"password_ref"`} {
		if !strings.Contains(got, field) {
			t.Errorf("no warning for the dropped field %s: %q", field, got)
		}
	}
	h, err := hosts[0].ToHost("putty")
	if err != nil {
		t.Fatal(err)
	}
	if h.Password != "" || h.PasswordMode != "" || h.PasswordRef != "" || len(h.KeyData) != 0 {
		t.Errorf("a secret got into the host: %+v", h)
	}
	if h.Key != "/home/u/.ssh/id" || len(h.Forwards) != 1 || h.Forwards[0].Name != "db" || len(h.Tags) != 2 {
		t.Errorf("host %+v", h)
	}
}

func TestParseImportRefuses(t *testing.T) {
	for name, in := range map[string]string{
		"not an object":  `[1,2]`,
		"no key":         `{"hosts":[{"host":"h","user":"u"}]}`,
		"a blank key":    `{"hosts":[{"key":"  ","host":"h","user":"u"}]}`,
		"a bad port":     `{"hosts":[{"key":"k","port":"x"}]}`,
		"not JSON":       `hosts: []`,
		"a host as text": `{"hosts":["web"]}`,
	} {
		if _, _, err := ParseImport([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var b strings.Builder
	b.WriteString(`{"hosts":[`)
	for i := 0; i <= importMaxHosts; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"key":"k","host":"h","user":"u"}`)
	}
	b.WriteString(`]}`)
	if _, _, err := ParseImport([]byte(b.String())); err == nil {
		t.Error("more hosts than the limit were taken")
	}
}

func TestHostIDIsStableAndPerExtension(t *testing.T) {
	a := HostID("putty", "web")
	if a != HostID("putty", "web") {
		t.Error("the same host got two IDs")
	}
	if a == HostID("putty", "db") || a == HostID("termius", "web") {
		t.Error("two hosts share an ID")
	}
	if len(a) != 32 {
		t.Errorf("ID %q is not 32 hex characters", a)
	}
}

func TestToHostRefusesABadForward(t *testing.T) {
	e := ExtHost{Key: "k", Host: "h", User: "u", Forwards: []string{"nonsense"}}
	if _, err := e.ToHost("x"); err == nil {
		t.Error("a bad forward was taken")
	}
}

func TestCollectCapsWhatAnImporterPrints(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the importer is a shell command")
	}
	out, err := Collect(exec.Command("sh", "-c", `echo '{"hosts":[]}'`))
	if err != nil || string(out) != `{"hosts":[]}` {
		t.Fatalf("%q, %v", out, err)
	}
	if _, err := Collect(exec.Command("sh", "-c", "head -c 9000000 /dev/zero")); err == nil || !strings.Contains(err.Error(), "more than 8 MiB") {
		t.Errorf("an endless importer: %v", err)
	}
	if _, err := Collect(exec.Command("sh", "-c", "exit 3")); err == nil || !strings.Contains(err.Error(), "failed") {
		t.Errorf("a failing importer: %v", err)
	}
}
