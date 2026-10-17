package ui

import (
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

// settingsPane is the highlighted settings sidebar item (page scrolls to it).
type settingsPane int

const (
	settingsAbout settingsPane = iota
	settingsLanguage
	settingsIntegrations
)

const appVersion = "0.01 alfa"

type authKind int

const (
	authPassword authKind = iota
	// authAsk is a password ssh asks for on every connect
	authAsk
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
	authDropBtn  widget.Clickable
	authOpen     bool
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

	addBtn           widget.Clickable
	settingsBtn      widget.Clickable
	hostsBtn         widget.Clickable
	backBtn          widget.Clickable
	aboutBtn         widget.Clickable
	langNavBtn       widget.Clickable
	integrBtn        widget.Clickable
	langBtns         []widget.Clickable
	langDropBtn      widget.Clickable
	langOpen         bool
	moshBox          widget.Bool
	reuseBox         widget.Bool
	healthBox        widget.Bool
	list             widget.List
	settingsList     widget.List
	settingsScrollTo int          // section index to jump to; -1 means none
	hostRows         []hostRowHit // parallel to hosts; secondary-click targets
	hostMenu         hostContextMenu
	uploads          chan uploadResult // finished image uploads from goroutines
	importBtn        widget.Clickable
	opSignInBtn      widget.Clickable
	exportBox        widget.Bool
	importing        bool
	imports          chan importResult
	opConnecting     bool
	opMsg            string // feedback under Connect 1Password (settings hides global status)
	opResults        chan opResult
	opModal          opModal
	uploading        bool
	modal            confirmModal // delete confirm
	form             formModal    // add/edit host
	settingsIC       *widget.Icon
	hostsIC          *widget.Icon
	dropIC           *widget.Icon
	logo             paint.ImageOp // About + branding, from assets/icons

	sidebarW float32
	split    splitDrag

	status string // soft status line under the title
	err    string // list-level error (form errors live in form.err)

	// allHosts is every saved host, hosts is what the search keeps of it,
	// hostRows follows hosts
	allHosts   []sshrapp.Host
	lastSearch string

	// health holds the last check of each host by ID, nil while checks
	// are off or the first one runs
	health     map[string]sshrapp.Health
	healthRes  chan map[string]sshrapp.Health
	healthStop chan struct{}
	healthKick chan struct{}
}

// hostRowHit is an event.Tag for secondary-click on one host row.
type hostRowHit struct{}

// hostContextMenu is the right-click Edit/Delete menu for one host.
type hostContextMenu struct {
	open   bool
	hostID string
	edit   widget.Clickable
	del    widget.Clickable
}

func (m *hostContextMenu) close() {
	m.open = false
	m.hostID = ""
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
	if len(s.hostRows) != len(s.hosts) {
		s.hostRows = make([]hostRowHit, len(s.hosts))
	}
	if s.hostMenu.open {
		found := false
		for _, h := range s.hosts {
			if h.ID == s.hostMenu.hostID {
				found = true
				break
			}
		}
		if !found {
			s.hostMenu.close()
		}
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
		s.hostMenu.close()
		s.clearForm()
		s.refreshStatus()
	}
	if s.settingsBtn.Clicked(gtx) {
		s.screen = screenSettings
		s.settingsPane = settingsAbout
		s.settingsScrollTo = int(settingsAbout)
		s.langOpen = false
		s.hostMenu.close()
		s.err = ""
	}
	for _, item := range s.settingsNav() {
		if item.btn.Clicked(gtx) {
			s.settingsPane = item.pane
			s.settingsScrollTo = int(item.pane)
			s.langOpen = false
		}
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
		s.hostMenu.close()
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
	if s.authDropBtn.Clicked(gtx) {
		s.authOpen = !s.authOpen
	}
	s.clickChoices(gtx)
	s.clickSettings(gtx)
	s.finishHealth()
	for i := range s.langBtns {
		if s.langBtns[i].Clicked(gtx) {
			s.setLang(i18n.Languages()[i].Code)
			s.langOpen = false
		}
	}
	s.handleHostRows(gtx)
	if s.hostMenu.edit.Clicked(gtx) {
		if h := s.hostByID(s.hostMenu.hostID); h != nil {
			s.hostMenu.close()
			s.openEditForm(*h)
		}
	}
	if s.hostMenu.del.Clicked(gtx) {
		if h := s.hostByID(s.hostMenu.hostID); h != nil {
			s.hostMenu.close()
			s.openDeleteConfirm(*h)
		}
	}
	if s.searchEd.Text() != s.lastSearch {
		s.applySearch()
	}
	s.finishUploads(gtx)
	s.finishImport(gtx)
	s.finishOPConnect(gtx)
	if s.importBtn.Clicked(gtx) {
		s.startImport()
	}
	if s.opSignInBtn.Clicked(gtx) {
		s.startOPConnect()
	}
	if s.opModal.open {
		_ = s.opModal.card.Clicked(gtx)
		if s.opModal.scrim.Clicked(gtx) {
			if s.opModal.blockScrim {
				s.opModal.blockScrim = false
			} else {
				s.opModal.close()
			}
		} else if s.opModal.blockScrim {
			s.opModal.blockScrim = false
		}
		for i := range s.opModal.pickBtns {
			if s.opModal.pickBtns[i].Clicked(gtx) {
				s.opModal.selected = i
			}
		}
		if s.opModal.cancel.Clicked(gtx) {
			s.opModal.close()
		}
		if s.opModal.connect.Clicked(gtx) {
			if i := s.opModal.selected; i >= 0 && i < len(s.opModal.accounts) {
				s.authorizeOP(s.opModal.accounts[i])
			}
		}
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

func (s *state) hostByID(id string) *sshrapp.Host {
	if id == "" {
		return nil
	}
	for i := range s.hosts {
		if s.hosts[i].ID == id {
			return &s.hosts[i]
		}
	}
	for i := range s.allHosts {
		if s.allHosts[i].ID == id {
			return &s.allHosts[i]
		}
	}
	return nil
}

// handleHostRows opens/closes the host context menu from pointer presses.
func (s *state) handleHostRows(gtx layout.Context) {
	for i := range s.hostRows {
		if i >= len(s.hosts) {
			break
		}
		for {
			ev, ok := gtx.Event(pointer.Filter{
				Target: &s.hostRows[i],
				Kinds:  pointer.Press,
			})
			if !ok {
				break
			}
			e, ok := ev.(pointer.Event)
			if !ok {
				continue
			}
			id := s.hosts[i].ID
			switch {
			case e.Buttons.Contain(pointer.ButtonSecondary):
				if s.hostMenu.open && s.hostMenu.hostID == id {
					s.hostMenu.close()
				} else {
					s.hostMenu.open = true
					s.hostMenu.hostID = id
				}
			case e.Buttons.Contain(pointer.ButtonPrimary):
				if s.hostMenu.open {
					s.hostMenu.close()
				}
			}
		}
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
	s.authOpen = false
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
	var d authDraft
	if msg := s.applyAuth(&d); msg != "" {
		s.form.err = msg
		return
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
		Key:           d.key,
		KeyMode:       d.keyMode,
		KeyData:       d.keyData,
		KeyPassphrase: d.passphrase,
		KeyRef:        d.keyRef,
		Agent:         d.agentName,
		AgentKey:      d.agentKey,
		KeyPub:        d.keyPub,
		PasswordRef:   d.passRef,
		PasswordMode:  d.passMode,
		Password:      d.password,
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
