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

	"sshr.dev/internal/i18n"
)

// layoutSettings shows About above the language picker.
func layoutSettings(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layoutAboutSection(gtx, th)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(24)}.Layout),
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

// layoutConnectionSection holds connect options; each one carries a short
// note on what it does and what it costs.
func layoutConnectionSection(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Body1(th, s.t("settings.connection"))
			l.Font.Weight = 600
			return l.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			cb := material.CheckBox(th, &s.moshBox, s.t("settings.mosh"))
			cb.Color = colFG
			cb.IconColor = colAccent
			return cb.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Caption(th, s.t("settings.mosh.hint"))
			l.Color = colMuted
			return l.Layout(gtx)
		}),
	)
}

func layoutAboutSection(gtx layout.Context, th *material.Theme) layout.Dimensions {
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
					paint.Fill(gtx.Ops, colPanel)
					return layout.Dimensions{Size: size}
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
