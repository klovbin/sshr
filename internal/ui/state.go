package ui

import (
	"errors"
	"strings"

	"gioui.org/app"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op/paint"
	"gioui.org/widget"

	sshrapp "sshr.dev/internal/app"
	"sshr.dev/internal/i18n"
)

// screen is the right-pane mode (hosts list vs settings).
type screen int

const (
	screenList screen = iota
	screenSettings
)

// settingsPane selects the left nav item inside settings.
type settingsPane int

const (
	settingsAbout settingsPane = iota
	settingsLanguage
)

const appVersion = "0.01 alfa"

type authKind int

const (
	authPassword authKind = iota
	authKey
	// authVault is a private key pasted into the form, stored in sshr
	authVault
	// authOP is the key of an SSH Key item in 1Password
	authOP
	// authBW is the key of an SSH Key item in Bitwarden
	authBW
	// authAgent is a key that stays in an ssh agent
	authAgent
)

// state holds UI widgets, vault data, and transient status/errors.
type state struct {
	store        *sshrapp.Store
	settings     sshrapp.Settings
	locale       i18n.Locale
	hosts        []sshrapp.Host
	screen       screen
	settingsPane settingsPane
	win          *app.Window

	// Host form editors (shown in form modal).
	nameEd       widget.Editor
	hostEd       widget.Editor
	userEd       widget.Editor
	portEd       widget.Editor
	keyEd        widget.Editor
	passEd       widget.Editor
	jumpEd       widget.Editor
	tagsEd       widget.Editor // "prod, db"
	searchEd     widget.Editor // filters the host list
	fwdEd        widget.Editor // one forward per line, "db -L 5432:localhost:5432"
	authKind     authKind
	authPassBtn  widget.Clickable
	authKeyBtn   widget.Clickable
	authVaultBtn widget.Clickable
	authOPBtn    widget.Clickable
	authBWBtn    widget.Clickable
	passBWBtn    widget.Clickable
	authAgentBtn widget.Clickable
	agentEd      widget.Editor // system, 1password or a socket path
	agentKeyEd   widget.Editor // fingerprint or comment of one agent key
	keyRefEd     widget.Editor // op:// reference of a 1Password key
	passRefEd    widget.Editor // op:// reference of a 1Password password
	passOPBtn    widget.Clickable
	keyPasteEd   widget.Editor // pasted private key
	keyPassEd    widget.Editor // its passphrase, if any
	// passMode is sshrapp.PasswordSaved or sshrapp.PasswordAsk
	passMode     string
	passSavedBtn widget.Clickable
	passAskBtn   widget.Clickable
	// session picker in the host form: "", tmux or zellij
	session          string
	sessionOffBtn    widget.Clickable
	sessionTmuxBtn   widget.Clickable
	sessionZellijBtn widget.Clickable

	addBtn       widget.Clickable
	settingsBtn  widget.Clickable
	hostsBtn     widget.Clickable
	backBtn      widget.Clickable
	aboutBtn     widget.Clickable
	langNavBtn   widget.Clickable
	langBtns     []widget.Clickable
	langDropBtn  widget.Clickable
	langOpen     bool
	moshBox      widget.Bool
	reuseBox     widget.Bool
	healthBox    widget.Bool
	list         widget.List
	hostDelBtns  []widget.Clickable // parallel to hosts
	hostEditBtns []widget.Clickable // parallel to hosts
	uploads      chan uploadResult  // finished image uploads from goroutines
	importBtn    widget.Clickable
	exportBox    widget.Bool
	importing    bool
	imports      chan importResult
	uploading    bool
	modal        confirmModal // delete confirm
	form         formModal    // add/edit host
	settingsIC   *widget.Icon
	hostsIC      *widget.Icon
	dropIC       *widget.Icon
	logo         paint.ImageOp // About + branding, from assets/icons

	sidebarW float32
	split    splitDrag

	status string // soft status line under the title
	err    string // list-level error (form errors live in form.err)

	// allHosts is every saved host, hosts is what the search keeps of it,
	// the row buttons follow hosts
	allHosts   []sshrapp.Host
	lastSearch string

	// health holds the last check of each host by ID, nil while checks
	// are off or the first one runs
	health     map[string]sshrapp.Health
	healthRes  chan map[string]sshrapp.Health
	healthStop chan struct{}
	healthKick chan struct{}
}

// splitDrag tracks sidebar resize via window-X pointer events.
type splitDrag struct {
	dragging bool
	pid      pointer.ID
}

func (s *state) t(key string, args ...any) string {
	return s.locale.T(key, args...)
}

func (s *state) reload() {
	hosts, err := s.store.List()
	if err != nil {
		s.err = err.Error()
		return
	}
	s.allHosts = hosts
	s.kickHealth()
	s.applySearch()
	if len(hosts) == 0 {
		s.status = s.t("status.empty")
	} else {
		s.status = s.t("status.count", len(hosts))
	}
}

// applySearch keeps the hosts that match the search field
func (s *state) applySearch() {
	s.lastSearch = s.searchEd.Text()
	s.hosts = sshrapp.Filter(s.allHosts, s.lastSearch)
	if len(s.hostDelBtns) != len(s.hosts) {
		s.hostDelBtns = make([]widget.Clickable, len(s.hosts))
		s.hostEditBtns = make([]widget.Clickable, len(s.hosts))
	}
}

func (s *state) refreshStatus() {
	s.err = ""
	s.reload()
}

// handle processes clicks for the current frame (before layout).
func (s *state) handle(gtx layout.Context) {
	if s.hostsBtn.Clicked(gtx) {
		s.screen = screenList
		s.langOpen = false
		s.clearForm()
		s.refreshStatus()
	}
	if s.settingsBtn.Clicked(gtx) {
		s.screen = screenSettings
		s.settingsPane = settingsLanguage
		s.langOpen = false
		s.err = ""
	}
	if s.aboutBtn.Clicked(gtx) {
		s.settingsPane = settingsAbout
		s.langOpen = false
	}
	if s.langNavBtn.Clicked(gtx) {
		s.settingsPane = settingsLanguage
	}
	if s.backBtn.Clicked(gtx) {
		s.screen = screenList
		s.langOpen = false
		s.refreshStatus()
	}
	if s.langDropBtn.Clicked(gtx) {
		s.langOpen = !s.langOpen
	}
	if s.addBtn.Clicked(gtx) {
		s.langOpen = false
		s.openAddForm()
	}
	if s.form.open {
		_ = s.form.card.Clicked(gtx) // absorb; never dismiss
		if s.form.scrim.Clicked(gtx) {
			if s.form.blockScrim {
				s.form.blockScrim = false // drain click that opened the modal
			} else {
				s.form.close()
				s.clearForm()
			}
		} else if s.form.blockScrim {
			s.form.blockScrim = false
		}
	}
	if s.form.cancel.Clicked(gtx) {
		s.form.close()
		s.clearForm()
	}
	if s.form.save.Clicked(gtx) {
		s.saveHost()
	}
	if s.authPassBtn.Clicked(gtx) {
		s.authKind = authPassword
	}
	if s.authKeyBtn.Clicked(gtx) {
		s.authKind = authKey
	}
	if s.authVaultBtn.Clicked(gtx) {
		s.authKind = authVault
	}
	if s.authOPBtn.Clicked(gtx) {
		s.authKind = authOP
	}
	if s.authBWBtn.Clicked(gtx) {
		s.authKind = authBW
	}
	if s.passBWBtn.Clicked(gtx) {
		s.passMode = sshrapp.PasswordBitwarden
	}
	if s.authAgentBtn.Clicked(gtx) {
		s.authKind = authAgent
	}
	if s.passOPBtn.Clicked(gtx) {
		s.passMode = sshrapp.PasswordOnePassword
	}
	if s.passSavedBtn.Clicked(gtx) {
		s.passMode = sshrapp.PasswordSaved
	}
	if s.passAskBtn.Clicked(gtx) {
		s.passMode = sshrapp.PasswordAsk
	}
	if s.sessionOffBtn.Clicked(gtx) {
		s.session = ""
	}
	if s.sessionTmuxBtn.Clicked(gtx) {
		s.session = sshrapp.SessionTmux
	}
	if s.sessionZellijBtn.Clicked(gtx) {
		s.session = sshrapp.SessionZellij
	}
	if s.moshBox.Update(gtx) {
		s.settings.Mosh = s.moshBox.Value
		_ = sshrapp.SaveSettings(s.settings)
	}
	if s.reuseBox.Update(gtx) {
		s.settings.Reuse = s.reuseBox.Value
		_ = sshrapp.SaveSettings(s.settings)
	}
	if s.healthBox.Update(gtx) {
		s.settings.HealthCheck = s.healthBox.Value
		_ = sshrapp.SaveSettings(s.settings)
		s.setHealth(s.healthBox.Value)
	}
	s.finishHealth()
	for i := range s.langBtns {
		if s.langBtns[i].Clicked(gtx) {
			s.setLang(i18n.Languages()[i].Code)
			s.langOpen = false
		}
	}
	for i := range s.hostDelBtns {
		if i >= len(s.hosts) {
			break
		}
		if i < len(s.hostEditBtns) && s.hostEditBtns[i].Clicked(gtx) {
			s.openEditForm(s.hosts[i])
		}
		if s.hostDelBtns[i].Clicked(gtx) {
			s.openDeleteConfirm(s.hosts[i])
		}
	}
	if s.searchEd.Text() != s.lastSearch {
		s.applySearch()
	}
	s.finishUploads(gtx)
	s.finishImport(gtx)
	if s.importBtn.Clicked(gtx) {
		s.startImport()
	}
	if s.exportBox.Update(gtx) {
		s.setExport(s.exportBox.Value)
	}
	if s.modal.open {
		_ = s.modal.card.Clicked(gtx) // absorb; never dismiss
		if s.modal.scrim.Clicked(gtx) {
			if s.modal.blockScrim {
				s.modal.blockScrim = false // drain click that opened the modal
			} else {
				s.modal.close()
			}
		} else if s.modal.blockScrim {
			s.modal.blockScrim = false
		}
	}
	if s.modal.cancel.Clicked(gtx) {
		s.modal.close()
	}
	if s.modal.confirm.Clicked(gtx) {
		s.confirmDelete()
	}
}

func (s *state) confirmDelete() {
	id := s.modal.hostID
	name := ""
	for _, h := range s.hosts {
		if h.ID == id {
			name = h.Name
			break
		}
	}
	s.modal.close()
	if id == "" {
		return
	}
	if err := s.store.Delete(id); err != nil {
		s.err = s.mapErr(err)
		return
	}
	s.err = ""
	s.reload()
	if name != "" {
		s.status = s.t("status.deleted", name)
	}
}

func (s *state) setLang(code string) {
	s.locale = i18n.New(code)
	s.settings.Lang = code
	_ = sshrapp.SaveSettings(s.settings)
	if s.win != nil {
		s.win.Option(app.Title(s.t("app.title")))
	}
	s.refreshStatus()
}

func (s *state) clearForm() {
	s.nameEd.SetText("")
	s.hostEd.SetText("")
	s.userEd.SetText("")
	s.portEd.SetText("22")
	s.keyEd.SetText("")
	s.passEd.SetText("")
	s.passEd.Mask = '•'
	s.jumpEd.SetText("")
	s.tagsEd.SetText("")
	s.fwdEd.SetText("")
	s.session = ""
	s.authKind = authPassword
	s.passMode = sshrapp.PasswordSaved
	s.keyPasteEd.SetText("")
	s.keyPassEd.SetText("")
	s.keyRefEd.SetText("")
	s.passRefEd.SetText("")
	s.agentEd.SetText("")
	s.agentKeyEd.SetText("")
	s.form.editID = ""
	s.form.vaultKeyPrint = ""
	s.form.hasSavedPassword = false
}

func (s *state) mapErr(err error) string {
	switch {
	case errors.Is(err, sshrapp.ErrHostEmpty):
		return s.t("err.host_empty")
	case errors.Is(err, sshrapp.ErrUserRequired):
		return s.t("err.user_required")
	case errors.Is(err, sshrapp.ErrPortInvalid):
		return s.t("err.port_invalid")
	case errors.Is(err, sshrapp.ErrNotFound):
		return s.t("err.not_found")
	case errors.Is(err, sshrapp.ErrNoKeychain):
		return s.t("err.noKeychain")
	case errors.Is(err, sshrapp.ErrPasswordRequired):
		return s.t("err.password_required")
	case errors.Is(err, sshrapp.ErrAsksPassword):
		return s.t("err.asksPassword")
	case errors.Is(err, sshrapp.ErrKeyPassphrase):
		return s.t("err.keyPassphrase")
	case errors.Is(err, sshrapp.ErrKeyRequired):
		return s.t("err.keyPaste_required")
	case errors.Is(err, sshrapp.ErrNoOP):
		return s.t("err.noOP")
	default:
		return err.Error()
	}
}

// editedHost is the saved host the form edits, nil for a new one
func (s *state) editedHost() *sshrapp.Host {
	for i := range s.allHosts {
		if s.form.editID != "" && s.allHosts[i].ID == s.form.editID {
			return &s.allHosts[i]
		}
	}
	return nil
}

func (s *state) saveHost() {
	port := 22
	if p := strings.TrimSpace(s.portEd.Text()); p != "" {
		n, err := sshrapp.ParsePort(p)
		if err != nil {
			s.form.err = s.t("err.port_invalid")
			return
		}
		port = n
	}
	key := ""
	password := ""
	passMode := ""
	keyMode, passphrase, keyRef, passRef := "", "", "", ""
	agentName, agentKey, keyPub := "", "", ""
	var keyData []byte
	if s.authKind == authAgent {
		keyMode = sshrapp.KeyAgent
		agentName = strings.TrimSpace(s.agentEd.Text())
		agentKey = strings.TrimSpace(s.agentKeyEd.Text())
		// the key chosen before is kept without asking the agent again
		if cur := s.editedHost(); cur != nil && cur.KeyMode == sshrapp.KeyAgent && cur.Agent == agentName && agentKey != "" && agentKey == cur.KeyFingerprint() {
			agentKey, keyPub = "", cur.KeyPub
		}
	} else if s.authKind == authOP {
		keyMode = sshrapp.KeyOnePassword
		keyRef = strings.TrimSpace(s.keyRefEd.Text())
		if keyRef == "" {
			s.form.err = s.t("err.opRef_required")
			return
		}
	} else if s.authKind == authBW {
		keyMode = sshrapp.KeyBitwarden
		keyRef = strings.TrimSpace(s.keyRefEd.Text())
		if keyRef == "" {
			s.form.err = s.t("err.bwRef_required")
			return
		}
		if cur := s.editedHost(); cur != nil && cur.KeyMode == sshrapp.KeyBitwarden && cur.KeyRef == keyRef {
			keyPub = cur.KeyPub
		}
	} else if s.authKind == authVault {
		keyMode = sshrapp.KeyVault
		if t := strings.TrimSpace(s.keyPasteEd.Text()); t != "" {
			keyData = []byte(t)
			passphrase = s.keyPassEd.Text()
		} else if s.form.vaultKeyPrint == "" {
			s.form.err = s.t("err.keyPaste_required")
			return
		}
	} else if s.authKind == authKey {
		key = strings.TrimSpace(s.keyEd.Text())
		if key == "" {
			s.form.err = s.t("err.key_required")
			return
		}
		key = sshrapp.ExpandHome(key)
		if err := sshrapp.CheckPrivateKey(key); err != nil {
			s.form.err = err.Error()
			return
		}
	} else if s.passMode == sshrapp.PasswordAsk {
		passMode = sshrapp.PasswordAsk
	} else if s.passMode == sshrapp.PasswordBitwarden {
		passMode = sshrapp.PasswordBitwarden
		passRef = strings.TrimSpace(s.passRefEd.Text())
		if passRef == "" {
			s.form.err = s.t("err.bwRef_required")
			return
		}
	} else if s.passMode == sshrapp.PasswordOnePassword {
		passMode = sshrapp.PasswordOnePassword
		passRef = strings.TrimSpace(s.passRefEd.Text())
		password = s.passEd.Text()
		if passRef == "" && password == "" {
			s.form.err = s.t("err.opPassword_required")
			return
		}
	} else {
		passMode = sshrapp.PasswordSaved
		// kept as typed, spaces at the ends can be part of a password
		password = s.passEd.Text()
		if password == "" && !s.form.hasSavedPassword {
			s.form.err = s.t("err.password_required")
			return
		}
	}
	forwards, err := sshrapp.ParseForwards(s.fwdEd.Text())
	if err != nil {
		s.form.err = err.Error()
		return
	}
	var h *sshrapp.Host
	in := sshrapp.Host{
		Name:          s.nameEd.Text(),
		Host:          s.hostEd.Text(),
		User:          s.userEd.Text(),
		Port:          port,
		Key:           key,
		KeyMode:       keyMode,
		KeyData:       keyData,
		KeyPassphrase: passphrase,
		KeyRef:        keyRef,
		Agent:         agentName,
		AgentKey:      agentKey,
		KeyPub:        keyPub,
		PasswordRef:   passRef,
		PasswordMode:  passMode,
		Password:      password,
		Jump:          s.jumpEd.Text(),
		Session:       s.session,
		Forwards:      forwards,
		Tags:          sshrapp.SplitTags(s.tagsEd.Text()),
	}
	if s.form.editID != "" {
		h, err = s.store.Update(s.form.editID, in)
	} else {
		h, err = s.store.Add(in)
	}
	if err != nil {
		s.form.err = s.mapErr(err)
		return
	}
	edited := s.form.editID != ""
	s.form.close()
	s.clearForm()
	s.err = ""
	s.reload()
	if edited {
		s.status = s.t("status.updated", h.Name)
	} else {
		s.status = s.t("status.added", h.Name)
	}
}
