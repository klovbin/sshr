package ui

import (
	"errors"
	"strconv"
	"strings"

	"gioui.org/app"
	"gioui.org/layout"
	"gioui.org/widget"
	"gioui.org/io/pointer"

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

// state holds UI widgets, vault data, and transient status/errors.
type state struct {
	store        *sshrapp.Store
	settings     sshrapp.Settings
	locale       i18n.Locale
	hosts        []sshrapp.Host
	screen       screen
	settingsPane settingsPane
	win          *app.Window

	// Add-host form editors (shown in form modal).
	nameEd widget.Editor
	hostEd widget.Editor
	userEd widget.Editor
	portEd widget.Editor

	addBtn      widget.Clickable
	settingsBtn widget.Clickable
	hostsBtn    widget.Clickable
	backBtn     widget.Clickable
	aboutBtn    widget.Clickable
	langNavBtn  widget.Clickable
	langBtns    []widget.Clickable
	langDropBtn widget.Clickable
	langOpen    bool
	list        widget.List
	hostDelBtns []widget.Clickable // parallel to hosts
	modal       confirmModal       // delete confirm
	form        formModal          // add host
	settingsIC  *widget.Icon
	hostsIC     *widget.Icon
	dropIC      *widget.Icon

	sidebarW float32
	split    splitDrag

	status string // soft status line under the title
	err    string // list-level error (form errors live in form.err)
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
	s.hosts = hosts
	if len(s.hostDelBtns) != len(hosts) {
		s.hostDelBtns = make([]widget.Clickable, len(hosts))
	}
	if len(hosts) == 0 {
		s.status = s.t("status.empty")
	} else {
		s.status = s.t("status.count", len(hosts))
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
		if s.hostDelBtns[i].Clicked(gtx) {
			s.openDeleteConfirm(s.hosts[i])
		}
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
}

func (s *state) mapErr(err error) string {
	switch {
	case errors.Is(err, sshrapp.ErrHostEmpty):
		return s.t("err.host_empty")
	case errors.Is(err, sshrapp.ErrUserRequired):
		return s.t("err.user_required")
	case errors.Is(err, sshrapp.ErrNotFound):
		return s.t("err.not_found")
	default:
		return err.Error()
	}
}

func (s *state) saveHost() {
	port := 22
	if p := strings.TrimSpace(s.portEd.Text()); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 {
			s.form.err = s.t("err.port_invalid")
			return
		}
		port = n
	}
	h, err := s.store.Add(s.nameEd.Text(), s.hostEd.Text(), s.userEd.Text(), "", port)
	if err != nil {
		s.form.err = s.mapErr(err)
		return
	}
	s.form.close()
	s.clearForm()
	s.err = ""
	s.reload()
	s.status = s.t("status.added", h.Name)
}
