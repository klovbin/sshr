package ui

import (
	"errors"
	"path/filepath"
	"strings"

	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	sshrapp "sshr.dev/internal/app"
)

// authDraft is what one auth option writes into a host before save.
type authDraft struct {
	key, password, passMode, keyMode, passphrase, keyRef, passRef string
	agentName, agentKey, keyPub                                   string
	keyData                                                       []byte
}

// authOpt is one entry in the auth dropdown: label, click, form fields, save, load.
// Menu order is the slice order. Host matching uses rank (lower wins) because
// a saved host can satisfy more than one option.
type authOpt struct {
	kind     authKind
	btn      *widget.Clickable
	labelKey string
	rank     int
	fields   func(th *material.Theme, s *state) []layout.FlexChild
	apply    func(s *state, d *authDraft) string
	match    func(h sshrapp.Host) bool
	load     func(s *state, h sshrapp.Host)
}

func (s *state) authOpts() []authOpt {
	return []authOpt{
		{
			kind: authPassword, btn: &s.authPassBtn, labelKey: "auth.password", rank: 60,
			fields: func(th *material.Theme, s *state) []layout.FlexChild { return s.passwordFields(th) },
			apply:  applyPassword,
			match:  func(sshrapp.Host) bool { return true },
			load:   loadPassword,
		},
		{
			kind: authAsk, btn: &s.passAskBtn, labelKey: "auth.pass.ask", rank: 55,
			apply: func(_ *state, d *authDraft) string {
				d.passMode = sshrapp.PasswordAsk
				return ""
			},
			match: func(h sshrapp.Host) bool {
				return h.Key == "" && h.KeyMode == "" && h.PasswordMode == sshrapp.PasswordAsk
			},
			load: clearKeyField,
		},
		{
			kind: authKey, btn: &s.authKeyBtn, labelKey: "auth.key", rank: 50,
			fields: func(th *material.Theme, s *state) []layout.FlexChild {
				return []layout.FlexChild{spacer(10), field(th, s.t("field.key"), &s.keyEd)}
			},
			apply: applyKeyFile,
			match: func(h sshrapp.Host) bool { return h.Key != "" },
			load: func(s *state, h sshrapp.Host) {
				s.keyEd.SetText(h.Key)
			},
		},
		{
			kind: authVault, btn: &s.authVaultBtn, labelKey: "auth.vault", rank: 40,
			fields: vaultFields,
			apply:  applyVault,
			match:  func(h sshrapp.Host) bool { return h.KeyMode == sshrapp.KeyVault },
			load:   loadVault,
		},
		{
			kind: authOP, btn: &s.authOPBtn, labelKey: "auth.opKey", rank: 20,
			fields: refFields("field.keyRef", "field.keyRef.hint"),
			apply:  applyKeyRef(sshrapp.KeyOnePassword, "err.opRef_required", false),
			match:  func(h sshrapp.Host) bool { return h.KeyMode == sshrapp.KeyOnePassword },
			load:   clearKeyField,
		},
		{
			kind: authBW, btn: &s.authBWBtn, labelKey: "auth.bwKey", rank: 30,
			fields: refFields("field.bwKeyRef", "field.bwRef.hint"),
			apply:  applyKeyRef(sshrapp.KeyBitwarden, "err.bwRef_required", true),
			match:  func(h sshrapp.Host) bool { return h.KeyMode == sshrapp.KeyBitwarden },
			load:   clearKeyField,
		},
		{
			kind: authAgent, btn: &s.authAgentBtn, labelKey: "auth.agent", rank: 10,
			fields: agentFields,
			apply:  applyAgent,
			match:  func(h sshrapp.Host) bool { return h.KeyMode == sshrapp.KeyAgent },
			load:   loadAgent,
		},
	}
}

// passOpt is one password-source button under auth "password".
type passOpt struct {
	mode   string
	btn    *widget.Clickable
	label  func(s *state) string
	active func(mode string) bool
	fields func(th *material.Theme, s *state) []layout.FlexChild
	apply  func(s *state, d *authDraft) string
}

func (s *state) passOpts() []passOpt {
	is := func(want string) func(string) bool {
		return func(mode string) bool { return mode == want }
	}
	return []passOpt{
		{
			mode: sshrapp.PasswordSaved, btn: &s.passSavedBtn,
			label:  func(s *state) string { return s.t("auth.pass.saved") },
			active: savedPass,
			fields: savedPassFields,
			apply:  applySavedPass,
		},
		{
			mode: sshrapp.PasswordOnePassword, btn: &s.passOPBtn,
			label:  func(*state) string { return "1Password" },
			active: is(sshrapp.PasswordOnePassword),
			fields: opPassFields,
			apply:  applyOPPass,
		},
		{
			mode: sshrapp.PasswordBitwarden, btn: &s.passBWBtn,
			label:  func(*state) string { return "Bitwarden" },
			active: is(sshrapp.PasswordBitwarden),
			fields: bwPassFields,
			apply:  applyBWPass,
		},
	}
}

// sessionOpt is one button in the session picker.
type sessionOpt struct {
	value string
	btn   *widget.Clickable
	label func(s *state) string
}

func (s *state) sessionOpts() []sessionOpt {
	return []sessionOpt{
		{value: "", btn: &s.sessionOffBtn, label: func(s *state) string { return s.t("session.off") }},
		{value: sshrapp.SessionTmux, btn: &s.sessionTmuxBtn, label: func(*state) string { return "tmux" }},
		{value: sshrapp.SessionZellij, btn: &s.sessionZellijBtn, label: func(*state) string { return "zellij" }},
	}
}

type choiceBtn struct {
	btn    *widget.Clickable
	label  string
	active bool
}

func (s *state) clickChoices(gtx layout.Context) {
	for _, a := range s.authOpts() {
		if a.btn.Clicked(gtx) {
			s.authKind = a.kind
			s.authOpen = false
		}
	}
	for _, p := range s.passOpts() {
		if p.btn.Clicked(gtx) {
			s.passMode = p.mode
		}
	}
	for _, c := range s.sessionOpts() {
		if c.btn.Clicked(gtx) {
			s.session = c.value
		}
	}
}

func (s *state) authLabel() string {
	for _, a := range s.authOpts() {
		if a.kind == s.authKind {
			return s.t(a.labelKey)
		}
	}
	return s.t("auth.password")
}

func (s *state) authExtra(th *material.Theme) []layout.FlexChild {
	for _, a := range s.authOpts() {
		if a.kind == s.authKind && a.fields != nil {
			return a.fields(th, s)
		}
	}
	return nil
}

func (s *state) applyAuth(d *authDraft) string {
	for _, a := range s.authOpts() {
		if a.kind == s.authKind && a.apply != nil {
			return a.apply(s, d)
		}
	}
	return ""
}

func (s *state) loadAuth(h sshrapp.Host) {
	opts := s.authOpts()
	best := -1
	for i := range opts {
		if opts[i].match != nil && opts[i].match(h) && (best < 0 || opts[i].rank < opts[best].rank) {
			best = i
		}
	}
	if best < 0 {
		return
	}
	s.authKind = opts[best].kind
	if opts[best].load != nil {
		opts[best].load(s, h)
	}
}

func layoutChoiceButtons(gtx layout.Context, th *material.Theme, items []choiceBtn) layout.Dimensions {
	children := make([]layout.FlexChild, 0, len(items)*2)
	for i, it := range items {
		it := it
		if i > 0 {
			children = append(children, layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout))
		}
		children = append(children, layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return authChoiceBtn(gtx, th, it.btn, it.label, it.active)
		}))
	}
	return layout.Flex{}.Layout(gtx, children...)
}

func hintChild(th *material.Theme, text string) layout.FlexChild {
	return layout.Rigid(func(gtx layout.Context) layout.Dimensions {
		l := material.Caption(th, text)
		l.Color = colMuted
		return layout.Inset{Top: unit.Dp(4)}.Layout(gtx, l.Layout)
	})
}

func refFields(labelKey, hintKey string) func(th *material.Theme, s *state) []layout.FlexChild {
	return func(th *material.Theme, s *state) []layout.FlexChild {
		return []layout.FlexChild{
			spacer(10), field(th, s.t(labelKey), &s.keyRefEd),
			hintChild(th, s.t(hintKey)),
		}
	}
}

func agentFields(th *material.Theme, s *state) []layout.FlexChild {
	return []layout.FlexChild{
		spacer(10), field(th, s.t("field.agent"), &s.agentEd),
		hintChild(th, s.t("field.agent.hint")),
		spacer(10), field(th, s.t("field.agentKey"), &s.agentKeyEd),
		hintChild(th, s.t("field.agentKey.hint")),
	}
}

func vaultFields(th *material.Theme, s *state) []layout.FlexChild {
	hint := s.t("field.keyPaste.hint")
	if s.form.vaultKeyPrint != "" {
		hint = s.t("field.keyPaste.keep", s.form.vaultKeyPrint)
	}
	return []layout.FlexChild{
		spacer(10), multilineField(th, s.t("field.keyPaste"), &s.keyPasteEd),
		hintChild(th, hint),
		spacer(10), passwordField(th, s.t("field.keyPassphrase"), &s.keyPassEd),
	}
}

func (s *state) passwordFields(th *material.Theme) []layout.FlexChild {
	out := []layout.FlexChild{
		spacer(10),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layoutPassModePicker(gtx, th, s)
		}),
	}
	for _, p := range s.passOpts() {
		if !p.active(s.passMode) {
			continue
		}
		if p.fields != nil {
			out = append(out, p.fields(th, s)...)
		}
		break
	}
	return out
}

func clearKeyField(s *state, _ sshrapp.Host) {
	s.keyEd.SetText("")
}

func loadAgent(s *state, h sshrapp.Host) {
	s.keyEd.SetText("")
	s.agentEd.SetText(h.Agent)
	s.agentKeyEd.SetText(h.KeyFingerprint())
}

func loadVault(s *state, h sshrapp.Host) {
	s.keyEd.SetText("")
	s.form.vaultKeyPrint = h.KeyFingerprint()
	if s.form.vaultKeyPrint == "" {
		s.form.vaultKeyPrint = "?"
	}
}

func loadPassword(s *state, h sshrapp.Host) {
	s.keyEd.SetText("")
	for _, mode := range []string{sshrapp.PasswordOnePassword, sshrapp.PasswordBitwarden} {
		if h.PasswordMode == mode {
			s.passMode = h.PasswordMode
			break
		}
	}
	s.form.hasSavedPassword = h.PasswordMode == sshrapp.PasswordSaved
}

func applyAgent(s *state, d *authDraft) string {
	d.keyMode = sshrapp.KeyAgent
	d.agentName = strings.TrimSpace(s.agentEd.Text())
	d.agentKey = strings.TrimSpace(s.agentKeyEd.Text())
	cur := s.editedHost()
	if cur != nil && cur.KeyMode == sshrapp.KeyAgent && cur.Agent == d.agentName && d.agentKey != "" && d.agentKey == cur.KeyFingerprint() {
		d.agentKey, d.keyPub = "", cur.KeyPub
	}
	return ""
}

func applyKeyRef(mode, errKey string, keepPub bool) func(s *state, d *authDraft) string {
	return func(s *state, d *authDraft) string {
		d.keyMode = mode
		d.keyRef = strings.TrimSpace(s.keyRefEd.Text())
		if d.keyRef == "" {
			return s.t(errKey)
		}
		cur := s.editedHost()
		if keepPub && cur != nil && cur.KeyMode == mode && cur.KeyRef == d.keyRef {
			d.keyPub = cur.KeyPub
		}
		return ""
	}
}

func applyVault(s *state, d *authDraft) string {
	d.keyMode = sshrapp.KeyVault
	if t := strings.TrimSpace(s.keyPasteEd.Text()); t != "" {
		d.keyData = []byte(t)
		d.passphrase = s.keyPassEd.Text()
		return ""
	}
	if s.form.vaultKeyPrint == "" {
		return s.t("err.keyPaste_required")
	}
	return ""
}

func applyKeyFile(s *state, d *authDraft) string {
	key := strings.TrimSpace(s.keyEd.Text())
	if key == "" {
		return s.t("err.key_required")
	}
	key = sshrapp.ExpandHome(key)
	if err := sshrapp.CheckPrivateKey(key); err != nil {
		return err.Error()
	}
	d.key = key
	return ""
}

func applyPassword(s *state, d *authDraft) string {
	for _, p := range s.passOpts() {
		if p.active(s.passMode) && p.apply != nil {
			return p.apply(s, d)
		}
	}
	return ""
}

func savedPass(mode string) bool {
	return mode != sshrapp.PasswordAsk && mode != sshrapp.PasswordOnePassword && mode != sshrapp.PasswordBitwarden
}

func savedPassFields(th *material.Theme, s *state) []layout.FlexChild {
	hintKey := "field.password.hint"
	if s.form.hasSavedPassword {
		hintKey = "field.password.keep"
	}
	return []layout.FlexChild{
		spacer(10), passwordField(th, s.t("field.password"), &s.passEd),
		hintChild(th, s.t(hintKey)),
	}
}

func opPassFields(th *material.Theme, s *state) []layout.FlexChild {
	return []layout.FlexChild{
		spacer(10), field(th, s.t("field.passRef"), &s.passRefEd),
		spacer(10), passwordField(th, s.t("field.password"), &s.passEd),
		hintChild(th, s.t("field.passRef.hint")),
	}
}

func bwPassFields(th *material.Theme, s *state) []layout.FlexChild {
	return []layout.FlexChild{
		spacer(10), field(th, s.t("field.bwPassRef"), &s.passRefEd),
		hintChild(th, s.t("field.bwRef.hint")),
	}
}

func applySavedPass(s *state, d *authDraft) string {
	d.passMode = sshrapp.PasswordSaved
	d.password = s.passEd.Text()
	if d.password == "" && !s.form.hasSavedPassword {
		return s.t("err.password_required")
	}
	return ""
}

func applyOPPass(s *state, d *authDraft) string {
	d.passMode = sshrapp.PasswordOnePassword
	d.passRef = strings.TrimSpace(s.passRefEd.Text())
	d.password = s.passEd.Text()
	if d.passRef == "" && d.password == "" {
		return s.t("err.opPassword_required")
	}
	return ""
}

func applyBWPass(s *state, d *authDraft) string {
	d.passMode = sshrapp.PasswordBitwarden
	d.passRef = strings.TrimSpace(s.passRefEd.Text())
	if d.passRef == "" {
		return s.t("err.bwRef_required")
	}
	return ""
}

// hostAuthLine is the short auth caption on a host row.
// Order matches the old list: a key path wins over key mode.
type hostAuthLine struct {
	when func(h sshrapp.Host) bool
	text func(s *state, h sshrapp.Host) string
}

func hostAuthLabel(s *state, h sshrapp.Host) string {
	lines := []hostAuthLine{
		{func(h sshrapp.Host) bool { return h.Key != "" }, func(s *state, h sshrapp.Host) string {
			return s.t("auth.key.short") + ": " + filepath.Base(h.Key)
		}},
		{func(h sshrapp.Host) bool { return h.KeyMode == sshrapp.KeyVault }, func(s *state, _ sshrapp.Host) string {
			return s.t("auth.vault.short")
		}},
		{func(h sshrapp.Host) bool { return h.KeyMode == sshrapp.KeyOnePassword }, func(s *state, _ sshrapp.Host) string {
			return s.t("auth.opKey.short")
		}},
		{func(h sshrapp.Host) bool { return h.KeyMode == sshrapp.KeyBitwarden }, func(s *state, _ sshrapp.Host) string {
			return s.t("auth.bwKey.short")
		}},
		{func(h sshrapp.Host) bool { return h.KeyMode == sshrapp.KeyAgent }, func(s *state, _ sshrapp.Host) string {
			return s.t("auth.agent.short")
		}},
		{func(h sshrapp.Host) bool { return h.PasswordMode == sshrapp.PasswordOnePassword }, func(s *state, _ sshrapp.Host) string {
			return s.t("auth.opPass.short")
		}},
		{func(h sshrapp.Host) bool { return h.PasswordMode == sshrapp.PasswordBitwarden }, func(s *state, _ sshrapp.Host) string {
			return s.t("auth.bwPass.short")
		}},
		{func(h sshrapp.Host) bool { return h.PasswordMode == sshrapp.PasswordSaved }, func(s *state, _ sshrapp.Host) string {
			return s.t("auth.password.short")
		}},
		{func(h sshrapp.Host) bool { return h.PasswordMode == sshrapp.PasswordAsk }, func(s *state, _ sshrapp.Host) string {
			return s.t("auth.ask.short")
		}},
	}
	for _, line := range lines {
		if line.when(h) {
			return line.text(s, h)
		}
	}
	return ""
}

var uiErrs = []struct {
	err error
	key string
}{
	{sshrapp.ErrHostEmpty, "err.host_empty"},
	{sshrapp.ErrUserRequired, "err.user_required"},
	{sshrapp.ErrPortInvalid, "err.port_invalid"},
	{sshrapp.ErrNotFound, "err.not_found"},
	{sshrapp.ErrNoKeychain, "err.noKeychain"},
	{sshrapp.ErrPasswordRequired, "err.password_required"},
	{sshrapp.ErrAsksPassword, "err.asksPassword"},
	{sshrapp.ErrKeyPassphrase, "err.keyPassphrase"},
	{sshrapp.ErrKeyRequired, "err.keyPaste_required"},
	{sshrapp.ErrNoOP, "err.noOP"},
	{sshrapp.ErrOPIntegrationOff, "err.opIntegration"},
	{sshrapp.ErrOPPrivacy, "err.opPrivacy"},
}

func (s *state) mapErr(err error) string {
	for _, e := range uiErrs {
		if errors.Is(err, e.err) {
			return s.t(e.key)
		}
	}
	return err.Error()
}
