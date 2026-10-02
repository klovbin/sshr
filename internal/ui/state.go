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

type screen int

const (
	screenList screen = iota
	screenForm
	screenSettings
)

type state struct {
	store    *sshrapp.Store
	settings sshrapp.Settings
	locale   i18n.Locale
	hosts    []sshrapp.Host
	screen   screen
	win      *app.Window

	nameEd widget.Editor
	hostEd widget.Editor
	userEd widget.Editor
	portEd widget.Editor

	addBtn      widget.Clickable
	saveBtn     widget.Clickable
	cancelBtn   widget.Clickable
	settingsBtn widget.Clickable
	hostsBtn    widget.Clickable
	backBtn     widget.Clickable
	langBtns    []widget.Clickable
	langDropBtn widget.Clickable
	langOpen    bool
	list        widget.List
	settingsIC  *widget.Icon
	hostsIC     *widget.Icon
	dropIC      *widget.Icon

	sidebarW float32
	split    splitDrag

	status string
	err    string
}

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

func (s *state) handle(gtx layout.Context) {
	if s.hostsBtn.Clicked(gtx) {
		s.screen = screenList
		s.langOpen = false
		s.clearForm()
		s.refreshStatus()
	}
	if s.settingsBtn.Clicked(gtx) {
		s.screen = screenSettings
		s.langOpen = false
		s.err = ""
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
		s.screen = screenForm
		s.langOpen = false
		s.err = ""
	}
	if s.cancelBtn.Clicked(gtx) {
		s.screen = screenList
		s.err = ""
		s.clearForm()
		s.refreshStatus()
	}
	if s.saveBtn.Clicked(gtx) {
		s.saveHost()
	}
	for i := range s.langBtns {
		if s.langBtns[i].Clicked(gtx) {
			s.setLang(i18n.Languages()[i].Code)
			s.langOpen = false
		}
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
	default:
		return err.Error()
	}
}

func (s *state) saveHost() {
	port := 22
	if p := strings.TrimSpace(s.portEd.Text()); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 {
			s.err = s.t("err.port_invalid")
			return
		}
		port = n
	}
	h, err := s.store.Add(s.nameEd.Text(), s.hostEd.Text(), s.userEd.Text(), port)
	if err != nil {
		s.err = s.mapErr(err)
		return
	}
	s.screen = screenList
	s.err = ""
	s.clearForm()
	s.reload()
	s.status = s.t("status.added", h.Name)
}
