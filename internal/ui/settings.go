package ui

import (
	"fmt"
	"image"
	"image/color"

	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	sshrapp "sshr.dev/internal/app"
	"sshr.dev/internal/i18n"
)

// settingsNavItem is one entry in the settings sidebar; click scrolls to that section.
type settingsNavItem struct {
	btn   *widget.Clickable
	label string
	pane  settingsPane
}

func (s *state) settingsNav() []settingsNavItem {
	return []settingsNavItem{
		{btn: &s.aboutBtn, label: s.t("sidebar.about"), pane: settingsAbout},
		{btn: &s.langNavBtn, label: s.t("settings.language"), pane: settingsLanguage},
		{btn: &s.integrBtn, label: s.t("sidebar.integrations"), pane: settingsIntegrations},
	}
}

// layoutSettings is one scrollable page; sidebar categories jump to a section.
func layoutSettings(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	s.settingsList.Axis = layout.Vertical
	if s.settingsScrollTo >= 0 {
		s.settingsList.Position.First = s.settingsScrollTo
		s.settingsList.Position.Offset = 0
		s.settingsScrollTo = -1
	}
	sections := []layout.Widget{
		func(gtx layout.Context) layout.Dimensions { return layoutAboutSection(gtx, th, s) },
		func(gtx layout.Context) layout.Dimensions { return layoutLanguageSection(gtx, th, s) },
		func(gtx layout.Context) layout.Dimensions { return layoutIntegrations(gtx, th, s) },
	}
	return material.List(th, &s.settingsList).Layout(gtx, len(sections), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Bottom: unit.Dp(24)}.Layout(gtx, sections[i])
	})
}

func layoutLanguageSection(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Body1(th, s.t("settings.language"))
			l.Font.Weight = 600
			return l.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layoutLangDropdown(gtx, th, s)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(24)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layoutConnectionSection(gtx, th, s)
		}),
	)
}

func layoutIntegrations(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Body1(th, s.t("sidebar.integrations"))
			l.Font.Weight = 600
			return l.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layoutImportSection(gtx, th, s)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(24)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layoutOPSection(gtx, th, s)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
		layoutNote(th, s.t("settings.bw.title"), s.t("settings.bw.hint")),
	)
}

func layoutOPSection(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	connected := s.settings.HasOPAccount()
	chip := s.t("btn.opConnect")
	chipActive := true
	if s.opConnecting {
		chip = s.t("status.opConnecting")
		chipActive = false
	} else if connected {
		chip = s.t("btn.opReconnect")
		chipActive = false
	}
	account := opAccountLabel(s.settings)
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			// Whole card opens the account modal; the chip is visual only.
			return s.opSignInBtn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Background{}.Layout(gtx,
					func(gtx layout.Context) layout.Dimensions {
						bg := colPanel
						if s.opSignInBtn.Hovered() {
							bg = colHover
						}
						r := gtx.Dp(unit.Dp(14))
						defer clip.UniformRRect(image.Rectangle{Max: gtx.Constraints.Min}, r).Push(gtx.Ops).Pop()
						paint.Fill(gtx.Ops, bg)
						return layout.Dimensions{Size: gtx.Constraints.Min}
					},
					func(gtx layout.Context) layout.Dimensions {
						return layout.UniformInset(unit.Dp(14)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return layoutOPMark(gtx, unit.Dp(44))
								}),
								layout.Rigid(layout.Spacer{Width: unit.Dp(14)}.Layout),
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											t := material.Body1(th, s.t("settings.op.title"))
											t.Font.Weight = 600
											t.Color = colFG
											return t.Layout(gtx)
										}),
										layout.Rigid(layout.Spacer{Height: unit.Dp(3)}.Layout),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											if account != "" {
												l := material.Caption(th, s.t("settings.op.connected", account))
												l.Color = colOK
												return l.Layout(gtx)
											}
											l := material.Caption(th, s.t("settings.op.hint"))
											l.Color = colMuted
											return l.Layout(gtx)
										}),
									)
								}),
								layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return layoutOPChip(gtx, th, chip, chipActive)
								}),
							)
						})
					},
				)
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if s.opModal.open {
				return layout.Dimensions{}
			}
			msg := s.opMsg
			if msg == "" {
				return layout.Dimensions{}
			}
			// Success line lives in the card via settings; skip duplicate.
			if !s.opConnecting && s.err == "" && account != "" {
				return layout.Dimensions{}
			}
			c := colMuted
			if s.err != "" {
				c = colErr
			} else if !s.opConnecting {
				c = colOK
			}
			l := material.Caption(th, msg)
			l.Color = c
			return layout.Inset{Top: unit.Dp(8), Left: unit.Dp(4)}.Layout(gtx, l.Layout)
		}),
	)
}

// layoutOPChip is a non-clickable status/action pill on the 1Password card.
func layoutOPChip(gtx layout.Context, th *material.Theme, label string, active bool) layout.Dimensions {
	bg := colAccent
	fg := colWhite
	if !active {
		bg = colBorder
		fg = colMuted
	}
	return layout.Background{}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			r := gtx.Dp(unit.Dp(8))
			defer clip.UniformRRect(image.Rectangle{Max: gtx.Constraints.Min}, r).Push(gtx.Ops).Pop()
			paint.Fill(gtx.Ops, bg)
			return layout.Dimensions{Size: gtx.Constraints.Min}
		},
		func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{
				Top: unit.Dp(8), Bottom: unit.Dp(8),
				Left: unit.Dp(16), Right: unit.Dp(16),
			}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				l := material.Label(th, unit.Sp(13), label)
				l.Color = fg
				l.Font.Weight = 600
				return l.Layout(gtx)
			})
		},
	)
}

func layoutNote(th *material.Theme, title, hint string) layout.FlexChild {
	return layout.Rigid(func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.Body1(th, title)
				l.Font.Weight = 600
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.Caption(th, hint)
				l.Color = colMuted
				return l.Layout(gtx)
			}),
		)
	})
}

// layoutImportSection brings hosts in from ~/.ssh/config
func layoutImportSection(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Body1(th, s.t("settings.import"))
			l.Font.Weight = 600
			return l.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			b := material.Button(th, &s.importBtn, s.t("btn.importSSHConfig"))
			b.Background = colAccent
			return b.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Caption(th, s.t("settings.import.hint"))
			l.Color = colMuted
			return l.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			cb := material.CheckBox(th, &s.exportBox, s.t("settings.export"))
			cb.Color = colFG
			cb.IconColor = colAccent
			return cb.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Caption(th, s.t("settings.export.hint"))
			l.Color = colMuted
			return l.Layout(gtx)
		}),
	)
}

// layoutConnectionSection holds connect options; each one carries a short
// note on what it does and what it costs.
func layoutConnectionSection(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	rows := s.settingRows()
	children := []layout.FlexChild{
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Body1(th, s.t("settings.connection"))
			l.Font.Weight = 600
			return l.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
	}
	for i, row := range rows {
		row := row
		if i > 0 {
			children = append(children, layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout))
		}
		children = append(children, layoutCheckRow(th, row)...)
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
}

type checkRow struct {
	box         *widget.Bool
	label, hint string
	set         func(*state, bool)
}

func (s *state) clickSettings(gtx layout.Context) {
	for _, row := range s.settingRows() {
		if row.box.Update(gtx) {
			row.set(s, row.box.Value)
			_ = sshrapp.SaveSettings(s.settings)
		}
	}
}

func (s *state) settingRows() []checkRow {
	return []checkRow{
		{box: &s.moshBox, label: s.t("settings.mosh"), hint: s.t("settings.mosh.hint"), set: func(s *state, v bool) { s.settings.Mosh = v }},
		{box: &s.reuseBox, label: s.t("settings.reuse"), hint: s.t("settings.reuse.hint"), set: func(s *state, v bool) { s.settings.Reuse = v }},
		{box: &s.healthBox, label: s.t("settings.health"), hint: s.t("settings.health.hint"), set: func(s *state, v bool) {
			s.settings.HealthCheck = v
			s.setHealth(v)
		}},
	}
}

func layoutCheckRow(th *material.Theme, row checkRow) []layout.FlexChild {
	return []layout.FlexChild{
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			cb := material.CheckBox(th, row.box, row.label)
			cb.Color = colFG
			cb.IconColor = colAccent
			return cb.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Caption(th, row.hint)
			l.Color = colMuted
			return l.Layout(gtx)
		}),
	}
}

func layoutAboutSection(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Body1(th, "About")
			l.Font.Weight = 600
			return l.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					sz := gtx.Dp(unit.Dp(56))
					size := image.Pt(sz, sz)
					radius := gtx.Dp(unit.Dp(12))
					defer clip.UniformRRect(image.Rectangle{Max: size}, radius).Push(gtx.Ops).Pop()
					if s.logo.Size() == (image.Point{}) {
						paint.Fill(gtx.Ops, colPanel)
						return layout.Dimensions{Size: size}
					}
					gtx.Constraints.Min = size
					gtx.Constraints.Max = size
					return widget.Image{
						Src:      s.logo,
						Fit:      widget.Cover,
						Position: layout.Center,
					}.Layout(gtx)
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(14)}.Layout),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							t := material.Body1(th, "sshr")
							t.Font.Weight = 600
							t.Color = colFG
							return t.Layout(gtx)
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							v := material.Caption(th, fmt.Sprintf("version: %s", appVersion))
							v.Color = colMuted
							v.Font.Weight = 500
							return v.Layout(gtx)
						}),
					)
				}),
			)
		}),
	)
}

func currentLangName(s *state) string {
	code := s.locale.Code()
	for _, lang := range i18n.Languages() {
		if lang.Code == code {
			return lang.Name
		}
	}
	return code
}

func layoutLangDropdown(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	radius := gtx.Dp(unit.Dp(10))
	border := colBorder
	bg := colField

	if s.langOpen {
		border = colAccent
		bg = colWhite
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return s.langDropBtn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return widget.Border{
					Color:        border,
					Width:        unit.Dp(1),
					CornerRadius: unit.Dp(10),
				}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Background{}.Layout(gtx,
						func(gtx layout.Context) layout.Dimensions {
							defer clip.UniformRRect(image.Rectangle{Max: gtx.Constraints.Min}, radius).Push(gtx.Ops).Pop()
							paint.Fill(gtx.Ops, bg)
							return layout.Dimensions{Size: gtx.Constraints.Min}
						},
						func(gtx layout.Context) layout.Dimensions {
							return layout.Inset{
								Top: unit.Dp(12), Bottom: unit.Dp(12),
								Left: unit.Dp(14), Right: unit.Dp(10),
							}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										l := material.Body1(th, currentLangName(s))
										l.Color = colFG
										return l.Layout(gtx)
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										if s.dropIC == nil {
											return layout.Dimensions{}
										}
										sz := gtx.Dp(unit.Dp(22))
										gtx.Constraints.Min = image.Pt(sz, sz)
										gtx.Constraints.Max = image.Pt(sz, sz)
										col := colMuted
										if s.langOpen {
											col = colAccent
										}
										return s.dropIC.Layout(gtx, col)
									}),
								)
							})
						},
					)
				})
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if !s.langOpen {
				return layout.Dimensions{}
			}
			return layout.Inset{Top: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return widget.Border{
					Color:        border,
					Width:        unit.Dp(1),
					CornerRadius: unit.Dp(10),
				}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Background{}.Layout(gtx,
						func(gtx layout.Context) layout.Dimensions {
							defer clip.UniformRRect(image.Rectangle{Max: gtx.Constraints.Min}, radius).Push(gtx.Ops).Pop()
							paint.Fill(gtx.Ops, colWhite)
							return layout.Dimensions{Size: gtx.Constraints.Min}
						},
						func(gtx layout.Context) layout.Dimensions {
							return layoutLangMenu(gtx, th, s)
						},
					)
				})
			})
		}),
	)
}

func layoutLangMenu(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	langs := i18n.Languages()
	children := make([]layout.FlexChild, 0, len(langs))
	for i, lang := range langs {
		i, lang := i, lang
		active := s.locale.Code() == lang.Code
		children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return s.langBtns[i].Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Background{}.Layout(gtx,
					func(gtx layout.Context) layout.Dimensions {
						rowBG := color.NRGBA{}
						if active {
							rowBG = colAccentSoft
						} else if s.langBtns[i].Hovered() {
							rowBG = colHover
						}
						if rowBG.A != 0 {
							defer clip.Rect{Max: gtx.Constraints.Min}.Push(gtx.Ops).Pop()
							paint.Fill(gtx.Ops, rowBG)
						}
						return layout.Dimensions{Size: gtx.Constraints.Min}
					},
					func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{
							Top: unit.Dp(12), Bottom: unit.Dp(12),
							Left: unit.Dp(14), Right: unit.Dp(12),
						}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									l := material.Body1(th, lang.Name)
									l.Color = colFG
									if active {
										l.Color = colAccent
										l.Font.Weight = 600
									}
									return l.Layout(gtx)
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									barW := gtx.Dp(unit.Dp(3))
									barH := gtx.Dp(unit.Dp(16))
									if !active {
										return layout.Dimensions{Size: image.Pt(barW, 0)}
									}
									size := image.Pt(barW, barH)
									defer clip.Rect{Max: size}.Push(gtx.Ops).Pop()
									paint.Fill(gtx.Ops, colAccent)
									return layout.Dimensions{Size: size}
								}),
							)
						})
					},
				)
			})
		}))
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
}
