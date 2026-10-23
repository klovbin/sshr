package app

import "testing"

func TestAuthLabels(t *testing.T) {
	for _, c := range []struct {
		h            Host
		short, label string
	}{
		{Host{Key: "/k/id_ed25519"}, "id_ed25519", "key file"},
		{Host{KeyMode: KeyVault}, "key (sshr)", "key stored in sshr"},
		{Host{KeyMode: KeyAgent}, "agent (system)", "key from an ssh agent"},
		{Host{KeyMode: KeyAgent, Agent: AgentOnePassword}, "agent (1password)", "key from an ssh agent"},
		{Host{KeyMode: KeyOnePassword}, "key (1password)", "key in 1Password"},
		{Host{KeyMode: KeyBitwarden}, "key (bitwarden)", "key in Bitwarden"},
		{Host{PasswordMode: PasswordSaved}, "password", "saved password"},
		{Host{PasswordMode: PasswordOnePassword}, "password (1password)", "password in 1Password"},
		{Host{PasswordMode: PasswordBitwarden}, "password (bitwarden)", "password in Bitwarden"},
		{Host{PasswordMode: PasswordAsk}, "ask", "password asked every time (not usable without a terminal)"},
		{Host{}, "-", "ssh config or agent"},
	} {
		if got := c.h.AuthShort(); got != c.short {
			t.Errorf("%+v short = %q, want %q", c.h, got, c.short)
		}
		if got := c.h.AuthLabel(); got != c.label {
			t.Errorf("%+v label = %q, want %q", c.h, got, c.label)
		}
	}
}

func TestBuildVersion(t *testing.T) {
	old := Version
	defer func() { Version = old }()
	Version = "v9.9.9"
	if BuildVersion() != "v9.9.9" {
		t.Error("the version set at build time is ignored")
	}
	Version = ""
	if BuildVersion() == "" {
		t.Error("no version without ldflags")
	}
}
