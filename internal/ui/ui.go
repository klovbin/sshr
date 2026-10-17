// Package ui is the Gio desktop shell: hosts list, settings, modals.
package ui

import (
	"bytes"
	"fmt"
	"image"
	_ "image/png"
	"os"

	"gioui.org/app"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"golang.org/x/exp/shiny/materialdesign/icons"

	"sshr.dev/assets"
	sshrapp "sshr.dev/internal/app"
	"sshr.dev/internal/i18n"
)

// Run opens the main window and blocks until the app exits.
func Run() {
	go func() {
		w := new(app.Window)
		w.Option(app.Size(unit.Dp(720), unit.Dp(560)))
		if err := loop(w); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}()
	app.Main()
}

func loadLogo() (paint.ImageOp, error) {
	b, err := assets.Icons.ReadFile("icons/sshr-128.png")
	if err != nil {
		return paint.ImageOp{}, err
	}
	img, _, err := image.Decode(bytes.NewReader(b))
	if err != nil {
		return paint.ImageOp{}, err
	}
	return paint.NewImageOp(img), nil
}

func loop(w *app.Window) error {
	th := material.NewTheme()
	store, err := sshrapp.DefaultStore()
	if err != nil {
		return err
	}
	settings, err := sshrapp.LoadSettings()
	if err != nil {
		return err
	}
	locale := i18n.New(settings.Lang)
	w.Option(app.Title(locale.T("app.title")))

	langs := i18n.Languages()
	hostsIC, err := widget.NewIcon(icons.HardwareComputer)
	if err != nil {
		return err
	}
	settingsIC, err := widget.NewIcon(icons.ActionSettings)
	if err != nil {
		return err
	}
	dropIC, err := widget.NewIcon(icons.NavigationArrowDropDown)
	if err != nil {
		return err
	}
	logo, err := loadLogo()
	if err != nil {
		return err
	}
	s := &state{
		store:      store,
		settings:   settings,
		locale:     locale,
		status:     locale.T("status.ready"),
		list:       widget.List{List: layout.List{Axis: layout.Vertical}},
		langBtns:   make([]widget.Clickable, len(langs)),
		hostsIC:    hostsIC,
		settingsIC: settingsIC,
		dropIC:     dropIC,
		logo:       logo,
		win:        w,
	}
	s.moshBox.Value = settings.Mosh
	s.reuseBox.Value = settings.Reuse
	s.healthBox.Value = settings.HealthCheck
	s.setHealth(settings.HealthCheck)
	s.exportBox.Value = store.SSHConfigExported()
	s.nameEd.SingleLine = true
	s.hostEd.SingleLine = true
	s.userEd.SingleLine = true
	s.portEd.SingleLine = true
	s.jumpEd.SingleLine = true
	s.portEd.SetText("22")
	s.reload()

	var ops op.Ops
	for {
		switch e := w.Event().(type) {
		case app.DestroyEvent:
			return e.Err
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)
			s.handle(gtx)
			layoutFrame(gtx, th, s)
			e.Frame(gtx.Ops)
		}
	}
}
