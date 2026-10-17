package ui

import (
	"errors"
	"image"
	"image/color"
	"strings"

	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	sshrapp "sshr.dev/internal/app"
)

type opResult struct {
	accounts []sshrapp.OPAccount
	err      error
	done     bool // authorize finished
	email    string
}

// opModal is the account picker before authorizing CLI access (Grok Bot style).
type opModal struct {
	open       bool
	accounts   []sshrapp.OPAccount
	selected   int
	pickBtns   []widget.Clickable
	connect    widget.Clickable
	cancel     widget.Clickable
	scrim      widget.Clickable
	card       widget.Clickable
	blockScrim bool
}

func (m *opModal) close() {
	m.open = false
	m.accounts = nil
	m.selected = 0
	m.pickBtns = nil
}

func (m *opModal) setAccounts(accounts []sshrapp.OPAccount) {
	m.accounts = accounts
	m.selected = 0
	m.pickBtns = make([]widget.Clickable, len(accounts))
	m.open = true
	m.blockScrim = true
}

func (s *state) startOPConnect() {
	if s.opConnecting {
		return
	}
	s.form.close()
	s.modal.close()
	s.opModal.close()
	s.opConnecting = true
	s.err = ""
	s.status = s.t("status.opConnecting")
	s.opMsg = s.status
	if s.opResults == nil {
		s.opResults = make(chan opResult, 1)
	} else {
		select {
		case <-s.opResults:
		default:
		}
	}
	if s.win != nil {
		s.win.Invalidate()
	}
	// Doc flow: op account list → pick account → op vault list --account (Touch ID).
	go func() {
		accounts, err := sshrapp.ListOPAccounts()
		s.opResults <- opResult{accounts: accounts, err: err}
		s.win.Invalidate()
	}()
}

func (s *state) finishOPConnect(gtx layout.Context) {
	select {
	case res := <-s.opResults:
		if res.done {
			s.opConnecting = false
			if res.err != nil {
				s.err = s.mapErr(res.err)
				s.opMsg = s.err
				s.handleOPConnectErr(res.err)
				if len(s.opModal.accounts) > 0 {
					s.opModal.open = true
				}
				return
			}
			s.opModal.close()
			s.err = ""
			s.status = s.t("status.opConnected", res.email)
			s.opMsg = s.status
			return
		}
		s.opConnecting = false
		if res.err != nil {
			s.err = s.mapErr(res.err)
			s.opMsg = s.err
			s.handleOPConnectErr(res.err)
			return
		}
		if len(res.accounts) == 0 {
			s.err = s.t("err.opNoAccounts")
			s.opMsg = s.err
			return
		}
		s.err = ""
		s.opMsg = ""
		s.opModal.setAccounts(res.accounts)
	default:
	}
}

func (s *state) handleOPConnectErr(err error) {
	switch {
	case errors.Is(err, sshrapp.ErrOPPrivacy):
		_ = sshrapp.OpenOPPrivacySettings()
		s.status = s.t("status.opNeedPrivacy")
		s.opMsg = s.status
	case errors.Is(err, sshrapp.ErrOPIntegrationOff):
		s.status = s.t("status.opNeedIntegration")
		s.opMsg = s.status
	}
}

func (s *state) authorizeOP(a sshrapp.OPAccount) {
	s.opConnecting = true
	s.status = s.t("status.opAuthorizing")
	s.opMsg = s.status
	if s.opResults == nil {
		s.opResults = make(chan opResult, 1)
	}
	go func() {
		err := sshrapp.AuthorizeOPAccount(a.Ref())
		if err == nil {
			s.settings.OPAccount = a.Ref()
			_ = sshrapp.SaveSettings(s.settings)
		}
		s.opResults <- opResult{done: true, err: err, email: a.Email}
		s.win.Invalidate()
	}()
}

func layoutOPModal(gtx layout.Context, th *material.Theme, s *state) {
	if !s.opModal.open {
		return
	}
	layoutModalCard(gtx, unit.Dp(400), unit.Dp(480), &s.opModal.scrim, &s.opModal.card, func(gtx layout.Context) layout.Dimensions {
		children := []layout.FlexChild{
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				t := material.H6(th, s.t("settings.op.title"))
				t.Color = colFG
				return t.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				b := material.Body2(th, s.t("modal.op.body"))
				b.Color = colMuted
				return b.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
		}
		for i := range s.opModal.accounts {
			i := i
			a := s.opModal.accounts[i]
			children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layoutOPAccountRow(gtx, th, &s.opModal.pickBtns[i], a, s.opModal.selected == i)
			}))
			children = append(children, layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout))
		}
		children = append(children,
			layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						btn := material.Button(th, &s.opModal.connect, s.t("btn.opConnect"))
						btn.Background = colAccent
						return btn.Layout(gtx)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						btn := material.Button(th, &s.opModal.cancel, s.t("btn.cancel"))
						btn.Background = colMuted
						return btn.Layout(gtx)
					}),
				)
			}),
		)
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
	})
}

func layoutOPAccountRow(gtx layout.Context, th *material.Theme, btn *widget.Clickable, a sshrapp.OPAccount, selected bool) layout.Dimensions {
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return widget.Border{
			Color:        colBorder,
			Width:        unit.Dp(1),
			CornerRadius: unit.Dp(10),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Background{}.Layout(gtx,
				func(gtx layout.Context) layout.Dimensions {
					bg := colField
					if selected {
						bg = colAccentSoft
					} else if btn.Hovered() {
						bg = colHover
					}
					r := gtx.Dp(unit.Dp(10))
					defer clip.UniformRRect(image.Rectangle{Max: gtx.Constraints.Min}, r).Push(gtx.Ops).Pop()
					paint.Fill(gtx.Ops, bg)
					return layout.Dimensions{Size: gtx.Constraints.Min}
				},
				func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{
						Top: unit.Dp(12), Bottom: unit.Dp(12),
						Left: unit.Dp(12), Right: unit.Dp(12),
					}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layoutOPRadio(gtx, selected)
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										l := material.Body1(th, a.Email)
										l.Color = colFG
										l.Font.Weight = 600
										return l.Layout(gtx)
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										url := a.URL
										if url != "" && !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
											url = "https://" + url + "/"
										}
										l := material.Caption(th, url)
										l.Color = colMuted
										return l.Layout(gtx)
									}),
								)
							}),
						)
					})
				},
			)
		})
	})
}

func layoutOPRadio(gtx layout.Context, on bool) layout.Dimensions {
	sz := gtx.Dp(unit.Dp(18))
	size := image.Pt(sz, sz)
	defer clip.Ellipse{Max: size}.Push(gtx.Ops).Pop()
	paint.Fill(gtx.Ops, colBorder)
	inner := gtx.Dp(unit.Dp(4))
	defer clip.Ellipse{
		Min: image.Pt(inner, inner),
		Max: image.Pt(sz-inner, sz-inner),
	}.Push(gtx.Ops).Pop()
	fill := color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}
	if on {
		fill = colAccent
	}
	paint.Fill(gtx.Ops, fill)
	return layout.Dimensions{Size: size}
}
