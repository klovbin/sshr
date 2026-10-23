package ui

import (
	"errors"
	"image"
	"image/color"
	"strconv"
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
	accounts  []sshrapp.OPAccount
	err       error
	done      bool // authorize finished
	email     string
	fromModal bool // list/add started while the OP sheet was open
}

// opModal is the 1Password integration sheet (detail or account picker).
type opModal struct {
	open       bool
	picking    bool // true = choose account; false = connected detail
	accounts   []sshrapp.OPAccount
	selected   int
	pickBtns   []widget.Clickable
	unlinkBtns []widget.Clickable
	connect    widget.Clickable
	cancel     widget.Clickable
	addBtn     widget.Clickable
	scrim      widget.Clickable
	card       widget.Clickable
	blockScrim bool
	msg        string // in-modal status/error (from Add inside the sheet)
}

func (m *opModal) close() {
	m.open = false
	m.picking = false
	m.accounts = nil
	m.selected = 0
	m.pickBtns = nil
	m.unlinkBtns = nil
	m.msg = ""
}

func (m *opModal) openDetail(n int) {
	m.open = true
	m.picking = false
	m.accounts = nil
	m.pickBtns = nil
	if n < 0 {
		n = 0
	}
	if len(m.unlinkBtns) != n {
		m.unlinkBtns = make([]widget.Clickable, n)
	}
	m.blockScrim = true
}

func (m *opModal) setAccounts(accounts []sshrapp.OPAccount) {
	m.accounts = accounts
	m.selected = 0
	m.pickBtns = make([]widget.Clickable, len(accounts))
	m.open = true
	m.picking = true
	m.blockScrim = true
}

func opAccountLabel(st sshrapp.Settings) string {
	st.NormalizeOPAccounts()
	switch len(st.OPAccounts) {
	case 0:
		if st.OPEmail != "" {
			return st.OPEmail
		}
		return st.OPAccount
	case 1:
		return st.OPAccounts[0].Label()
	default:
		return st.OPAccounts[0].Label() + " +" + strconv.Itoa(len(st.OPAccounts)-1)
	}
}

func (s *state) startOPConnect() {
	if s.opConnecting {
		return
	}
	s.form.close()
	s.modal.close()
	s.opModal.close()
	s.settings.NormalizeOPAccounts()
	// Already linked: show detail sheet, not the picker.
	if s.settings.HasOPAccount() {
		s.err = ""
		s.opMsg = ""
		s.opModal.openDetail(len(s.settings.OPAccounts))
		return
	}
	s.beginOPAccountList()
}

func (s *state) beginOPAccountList() {
	if s.opConnecting {
		return
	}
	fromModal := s.opModal.open
	s.opConnecting = true
	s.err = ""
	s.status = s.t("status.opConnecting")
	if fromModal {
		s.opMsg = ""
		s.opModal.msg = s.status
	} else {
		s.opMsg = s.status
	}
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
	go func() {
		accounts, err := sshrapp.ListOPAccounts()
		s.opResults <- opResult{accounts: accounts, err: err, fromModal: fromModal}
		s.win.Invalidate()
	}()
}

func (s *state) unlinkOP(i int) {
	s.settings.RemoveOPAccount(i)
	_ = sshrapp.SaveSettings(s.settings)
	s.opMsg = ""
	s.err = ""
	if !s.settings.HasOPAccount() {
		s.status = s.t("status.ready")
		s.opModal.close()
		return
	}
	s.opModal.openDetail(len(s.settings.OPAccounts))
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
					s.opModal.picking = true
				}
				return
			}
			s.err = ""
			s.status = s.t("status.opConnected", res.email)
			s.opMsg = s.status
			s.opModal.openDetail(len(s.settings.OPAccounts))
			return
		}
		s.opConnecting = false
		if res.err != nil {
			s.err = s.mapErr(res.err)
			s.opMsg = s.err
			s.handleOPConnectErr(res.err)
			return
		}
		accounts := s.filterNewOPAccounts(res.accounts)
		if len(accounts) == 0 {
			msg := s.t("err.opAllLinked")
			if len(res.accounts) == 0 {
				msg = s.t("err.opNoAccounts")
			}
			if res.fromModal || s.settings.HasOPAccount() {
				s.err = ""
				s.opMsg = ""
				s.opModal.openDetail(len(s.settings.OPAccounts))
				s.opModal.msg = msg
				return
			}
			s.err = msg
			s.opMsg = msg
			return
		}
		s.err = ""
		s.opMsg = ""
		s.opModal.msg = ""
		s.rememberOPAccount(res.accounts)
		s.opModal.setAccounts(accounts)
	default:
	}
}

func (s *state) filterNewOPAccounts(all []sshrapp.OPAccount) []sshrapp.OPAccount {
	s.settings.NormalizeOPAccounts()
	linked := make(map[string]bool, len(s.settings.OPAccounts))
	for _, a := range s.settings.OPAccounts {
		linked[a.Ref] = true
		if a.Email != "" {
			linked[a.Email] = true
		}
	}
	var out []sshrapp.OPAccount
	for _, a := range all {
		if linked[a.Ref()] || linked[a.Email] || linked[a.URL] || linked[a.UserUUID] {
			continue
		}
		out = append(out, a)
	}
	return out
}

// rememberOPAccount refreshes email labels for already linked accounts.
func (s *state) rememberOPAccount(accounts []sshrapp.OPAccount) {
	s.settings.NormalizeOPAccounts()
	changed := false
	for i, linked := range s.settings.OPAccounts {
		for _, a := range accounts {
			if a.Ref() != linked.Ref && a.URL != linked.Ref && a.Email != linked.Ref && a.UserUUID != linked.Ref {
				continue
			}
			if a.Email != "" && s.settings.OPAccounts[i].Email != a.Email {
				s.settings.OPAccounts[i].Email = a.Email
				changed = true
			}
			if ref := a.Ref(); ref != "" && s.settings.OPAccounts[i].Ref != ref {
				s.settings.OPAccounts[i].Ref = ref
				changed = true
			}
			break
		}
	}
	if changed {
		_ = sshrapp.SaveSettings(s.settings)
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
			s.settings.AddOPAccount(a.Ref(), a.Email)
			if err := sshrapp.SaveSettings(s.settings); err != nil {
				s.opResults <- opResult{done: true, err: err, email: a.Email}
				s.win.Invalidate()
				return
			}
		}
		s.opResults <- opResult{done: true, err: err, email: a.Label()}
		s.win.Invalidate()
	}()
}

func layoutOPModal(gtx layout.Context, th *material.Theme, s *state) {
	if !s.opModal.open {
		return
	}
	layoutModalCard(gtx, unit.Dp(440), unit.Dp(560), &s.opModal.scrim, &s.opModal.card, func(gtx layout.Context) layout.Dimensions {
		if s.opModal.picking {
			return layoutOPModalPicker(gtx, th, s)
		}
		return layoutOPModalDetail(gtx, th, s)
	})
}

func layoutOPModalDetail(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	s.settings.NormalizeOPAccounts()
	accounts := s.settings.OPAccounts
	connected := len(accounts) > 0
	if n := len(accounts); len(s.opModal.unlinkBtns) != n {
		s.opModal.unlinkBtns = make([]widget.Clickable, n)
	}
	children := []layout.FlexChild{
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layoutOPModalHeader(gtx, th, s, connected)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			b := material.Body2(th, s.t("modal.op.body"))
			b.Color = colMuted
			return b.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
	}
	for i := range accounts {
		i := i
		a := accounts[i]
		children = append(children,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layoutOPLinkedCard(gtx, th, s, a, &s.opModal.unlinkBtns[i])
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
		)
	}
	children = append(children,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if s.opModal.msg == "" {
				return layout.Dimensions{}
			}
			return layout.Inset{Top: unit.Dp(12)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layoutOPModalBanner(gtx, th, s.opModal.msg, s.opConnecting)
			})
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			btn := material.Button(th, &s.opModal.addBtn, s.t("btn.opAdd"))
			btn.Background = colAccent
			return btn.Layout(gtx)
		}),
	)
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
}

func layoutOPModalBanner(gtx layout.Context, th *material.Theme, msg string, connecting bool) layout.Dimensions {
	bg := color.NRGBA{R: 0xff, G: 0xf6, B: 0xe8, A: 0xff}
	fg := color.NRGBA{R: 0x8a, G: 0x5a, B: 0x12, A: 0xff}
	bar := colWarn
	if connecting {
		bg = colPanel
		fg = colMuted
		bar = colBorder
	}
	return widget.Border{
		Color:        color.NRGBA{R: bar.R, G: bar.G, B: bar.B, A: 0x55},
		Width:        unit.Dp(1),
		CornerRadius: unit.Dp(10),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Background{}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				r := gtx.Dp(unit.Dp(10))
				defer clip.UniformRRect(image.Rectangle{Max: gtx.Constraints.Min}, r).Push(gtx.Ops).Pop()
				paint.Fill(gtx.Ops, bg)
				return layout.Dimensions{Size: gtx.Constraints.Min}
			},
			func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{
					Top: unit.Dp(12), Bottom: unit.Dp(12),
					Left: unit.Dp(14), Right: unit.Dp(14),
				}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							sz := gtx.Dp(unit.Dp(8))
							defer clip.Ellipse{Max: image.Pt(sz, sz)}.Push(gtx.Ops).Pop()
							paint.Fill(gtx.Ops, bar)
							return layout.Dimensions{Size: image.Pt(sz, sz)}
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							l := material.Body2(th, msg)
							l.Color = fg
							return l.Layout(gtx)
						}),
					)
				})
			},
		)
	})
}

func layoutOPModalPicker(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	children := []layout.FlexChild{
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layoutOPModalHeader(gtx, th, s, false)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			b := material.Body2(th, s.t("modal.op.pick"))
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
					label := s.t("btn.cancel")
					if s.settings.HasOPAccount() {
						label = s.t("btn.back")
					}
					btn := material.Button(th, &s.opModal.cancel, label)
					btn.Background = colMuted
					return btn.Layout(gtx)
				}),
			)
		}),
	)
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
}

func layoutOPModalHeader(gtx layout.Context, th *material.Theme, s *state, connected bool) layout.Dimensions {
	return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layoutOPMark(gtx, unit.Dp(40))
		}),
		layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			t := material.H6(th, s.t("settings.op.title"))
			t.Color = colFG
			return t.Layout(gtx)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if !connected {
				return layout.Dimensions{}
			}
			l := material.Caption(th, "✓  "+s.t("btn.opReconnect"))
			l.Color = colOK
			l.Font.Weight = 600
			return l.Layout(gtx)
		}),
	)
}

func layoutOPLinkedCard(gtx layout.Context, th *material.Theme, s *state, a sshrapp.OPLinkedAccount, unlink *widget.Clickable) layout.Dimensions {
	return layout.Background{}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			r := gtx.Dp(unit.Dp(12))
			defer clip.UniformRRect(image.Rectangle{Max: gtx.Constraints.Min}, r).Push(gtx.Ops).Pop()
			paint.Fill(gtx.Ops, colField)
			return layout.Dimensions{Size: gtx.Constraints.Min}
		},
		func(gtx layout.Context) layout.Dimensions {
			return layout.UniformInset(unit.Dp(14)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								l := material.Body1(th, a.Label())
								l.Color = colFG
								l.Font.Weight = 600
								return l.Layout(gtx)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								l := material.Caption(th, s.t("modal.op.meta"))
								l.Color = colMuted
								return l.Layout(gtx)
							}),
						)
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layoutOPGhostBtn(gtx, th, unlink, s.t("btn.delete"))
					}),
				)
			})
		},
	)
}

func layoutOPGhostBtn(gtx layout.Context, th *material.Theme, btn *widget.Clickable, label string) layout.Dimensions {
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return widget.Border{
			Color:        colBorder,
			Width:        unit.Dp(1),
			CornerRadius: unit.Dp(8),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Background{}.Layout(gtx,
				func(gtx layout.Context) layout.Dimensions {
					bg := colWhite
					if btn.Hovered() {
						bg = colHover
					}
					r := gtx.Dp(unit.Dp(8))
					defer clip.UniformRRect(image.Rectangle{Max: gtx.Constraints.Min}, r).Push(gtx.Ops).Pop()
					paint.Fill(gtx.Ops, bg)
					return layout.Dimensions{Size: gtx.Constraints.Min}
				},
				func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{
						Top: unit.Dp(6), Bottom: unit.Dp(6),
						Left: unit.Dp(10), Right: unit.Dp(10),
					}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						l := material.Caption(th, label)
						l.Color = colFG
						l.Font.Weight = 500
						return l.Layout(gtx)
					})
				},
			)
		})
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
