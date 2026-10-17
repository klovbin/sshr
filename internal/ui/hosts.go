package ui

import (
	"fmt"
	"image"
	"image/color"
	"strings"

	"gioui.org/io/event"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// layoutHostsList renders hosts in the left Servers sidebar.
func layoutHostsList(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	if len(s.hosts) == 0 {
		msg := s.t("list.empty")
		if len(s.allHosts) > 0 {
			msg = s.t("list.noMatch")
		}
		empty := material.Caption(th, msg)
		empty.Color = colMuted
		return empty.Layout(gtx)
	}
	return material.List(th, &s.list).Layout(gtx, len(s.hosts), func(gtx layout.Context, i int) layout.Dimensions {
		return layout.Inset{Top: unit.Dp(4), Bottom: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layoutHostRow(gtx, th, s, i)
		})
	})
}

func layoutHostRow(gtx layout.Context, th *material.Theme, s *state, i int) layout.Dimensions {
	h := s.hosts[i]
	authLabel := hostAuthLabel(s, h)
	menuOpen := s.hostMenu.open && s.hostMenu.hostID == h.ID

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layoutHostRowHit(gtx, s, i, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Alignment: layout.Baseline}.Layout(gtx,
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								t := material.Body1(th, h.Name)
								t.Font.Weight = 600
								t.Color = colFG
								t.MaxLines = 1
								return t.Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								r, ok := s.health[h.ID]
								if !ok {
									return layout.Dimensions{}
								}
								l := material.Caption(th, "● "+s.healthLabel(r))
								l.Color = healthColor(r.State)
								l.MaxLines = 1
								return layout.Inset{Left: unit.Dp(8)}.Layout(gtx, l.Layout)
							}),
						)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						line := fmt.Sprintf("%s@%s:%d", h.User, h.Host, h.Port)
						sub := material.Caption(th, line)
						sub.Color = colMuted
						sub.MaxLines = 1
						return sub.Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						sub := material.Caption(th, authLabel)
						sub.Color = colMutedSoft
						sub.MaxLines = 1
						return sub.Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						if len(h.Tags) == 0 {
							return layout.Dimensions{}
						}
						sub := material.Caption(th, "#"+strings.Join(h.Tags, " #"))
						sub.Color = colAccent
						sub.MaxLines = 1
						return sub.Layout(gtx)
					}),
				)
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if !menuOpen {
				return layout.Dimensions{}
			}
			return layout.Inset{Top: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layoutHostContextMenu(gtx, th, s)
			})
		}),
	)
}

// layoutHostRowHit registers a pointer target so right-click opens the menu.
func layoutHostRowHit(gtx layout.Context, s *state, i int, w layout.Widget) layout.Dimensions {
	if i >= len(s.hostRows) {
		return w(gtx)
	}
	rec := op.Record(gtx.Ops)
	dims := w(gtx)
	call := rec.Stop()
	defer clip.Rect{Max: dims.Size}.Push(gtx.Ops).Pop()
	event.Op(gtx.Ops, &s.hostRows[i])
	call.Add(gtx.Ops)
	return dims
}

func layoutHostContextMenu(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	radius := gtx.Dp(unit.Dp(10))
	return widget.Border{
		Color:        colBorder,
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
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layoutHostMenuItem(gtx, th, &s.hostMenu.edit, s.t("btn.edit"), colFG)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layoutHostMenuItem(gtx, th, &s.hostMenu.del, s.t("btn.delete"), colErr)
					}),
				)
			},
		)
	})
}

func layoutHostMenuItem(gtx layout.Context, th *material.Theme, btn *widget.Clickable, label string, fg color.NRGBA) layout.Dimensions {
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Background{}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				if btn.Hovered() {
					defer clip.Rect{Max: gtx.Constraints.Min}.Push(gtx.Ops).Pop()
					paint.Fill(gtx.Ops, colHover)
				}
				return layout.Dimensions{Size: gtx.Constraints.Min}
			},
			func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{
					Top: unit.Dp(10), Bottom: unit.Dp(10),
					Left: unit.Dp(12), Right: unit.Dp(12),
				}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					l := material.Body1(th, label)
					l.Color = fg
					return l.Layout(gtx)
				})
			},
		)
	})
}

// layoutHostsMain is the right pane when Servers is active (list lives in sidebar).
func layoutHostsMain(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	msg := s.t("sidebar.hosts.main")
	if len(s.hosts) == 0 {
		msg = s.t("list.empty")
	}
	body := material.Body1(th, msg)
	body.Color = colMuted
	body.Alignment = text.Middle
	return layout.Center.Layout(gtx, body.Layout)
}

// layoutForm is the add/edit host fields used inside the form modal.
func layoutForm(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	children := []layout.FlexChild{
		field(th, s.t("field.name"), &s.nameEd),
		spacer(10),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layoutHostPort(gtx, th, s)
		}),
		spacer(10),
		field(th, s.t("field.user"), &s.userEd),
		spacer(12),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layoutAuthPicker(gtx, th, s)
		}),
	}
	children = append(children, s.authExtra(th)...)
	children = append(children, spacer(12), field(th, s.t("field.jump"), &s.jumpEd),
		hintChild(th, s.t("field.jump.hint")),
		spacer(12),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layoutSessionPicker(gtx, th, s)
		}),
		spacer(12),
		multilineField(th, s.t("field.forwards"), &s.fwdEd),
		hintChild(th, s.t("field.forwards.hint")),
		spacer(12),
		field(th, s.t("field.tags"), &s.tagsEd),
		hintChild(th, s.t("field.tags.hint")))
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
}

// layoutSessionPicker chooses what connect opens on the server: a plain
// shell, or a tmux/zellij session that survives a dropped connection
func layoutSessionPicker(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	opts := s.sessionOpts()
	items := make([]choiceBtn, len(opts))
	for i, c := range opts {
		items[i] = choiceBtn{btn: c.btn, label: c.label(s), active: s.session == c.value}
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Caption(th, s.t("field.session"))
			l.Color = colMuted
			return l.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layoutChoiceButtons(gtx, th, items)
		}),
		hintChild(th, s.t("field.session.hint")),
	)
}

// layoutPassModePicker chooses between a password saved encrypted in sshr
// and one typed on every connect
func layoutPassModePicker(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	opts := s.passOpts()
	items := make([]choiceBtn, len(opts))
	for i, p := range opts {
		items[i] = choiceBtn{btn: p.btn, label: p.label(s), active: p.active(s.passMode)}
	}
	return layoutChoiceButtons(gtx, th, items)
}

func layoutAuthPicker(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	radius := gtx.Dp(unit.Dp(10))
	border := colBorder
	bg := colField
	if s.authOpen {
		border = colAccent
		bg = colWhite
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Caption(th, s.t("field.auth"))
			l.Color = colMuted
			return l.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return s.authDropBtn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
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
								Top: unit.Dp(10), Bottom: unit.Dp(10),
								Left: unit.Dp(12), Right: unit.Dp(10),
							}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										l := material.Body1(th, s.authLabel())
										l.Color = colFG
										return l.Layout(gtx)
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										if s.dropIC == nil {
											return layout.Dimensions{}
										}
										sz := gtx.Dp(unit.Dp(20))
										gtx.Constraints.Min = image.Pt(sz, sz)
										gtx.Constraints.Max = image.Pt(sz, sz)
										col := colMuted
										if s.authOpen {
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
			if !s.authOpen {
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
							return layoutAuthMenu(gtx, th, s)
						},
					)
				})
			})
		}),
	)
}

func layoutAuthMenu(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	items := s.authOpts()
	children := make([]layout.FlexChild, 0, len(items))
	for _, it := range items {
		it := it
		active := s.authKind == it.kind
		children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return it.btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Background{}.Layout(gtx,
					func(gtx layout.Context) layout.Dimensions {
						rowBG := color.NRGBA{}
						if active {
							rowBG = colAccentSoft
						} else if it.btn.Hovered() {
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
							Top: unit.Dp(10), Bottom: unit.Dp(10),
							Left: unit.Dp(12), Right: unit.Dp(12),
						}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									l := material.Body1(th, s.t(it.labelKey))
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

func authChoiceBtn(gtx layout.Context, th *material.Theme, btn *widget.Clickable, label string, active bool) layout.Dimensions {
	b := material.Button(th, btn, label)
	b.TextSize = unit.Sp(13)
	b.Inset = layout.Inset{
		Top: unit.Dp(8), Bottom: unit.Dp(8),
		Left: unit.Dp(10), Right: unit.Dp(10),
	}
	if active {
		b.Background = colAccent
	} else {
		b.Background = colMuted
	}
	return b.Layout(gtx)
}

// layoutHostPort is host and port on one row: [host] : [port]
func layoutHostPort(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Caption(th, s.t("field.host"))
			l.Color = colMuted
			return l.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					s.hostEd.Submit = false
					s.hostEd.SingleLine = true
					return layoutEditorBox(gtx, material.Editor(th, &s.hostEd, s.t("field.host")).Layout)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					sep := material.Body1(th, ":")
					sep.Color = colMuted
					return layout.Inset{Left: unit.Dp(8), Right: unit.Dp(8)}.Layout(gtx, sep.Layout)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					gtx.Constraints.Min.X = gtx.Dp(unit.Dp(72))
					gtx.Constraints.Max.X = gtx.Dp(unit.Dp(88))
					s.portEd.Submit = false
					s.portEd.SingleLine = true
					return layoutEditorBox(gtx, material.Editor(th, &s.portEd, s.t("field.port")).Layout)
				}),
			)
		}),
	)
}

// layoutEditorBox draws a bordered input so empty fields stay visible.
func layoutEditorBox(gtx layout.Context, content layout.Widget) layout.Dimensions {
	radius := unit.Dp(10)
	return widget.Border{
		Color:        colInputBorder,
		Width:        unit.Dp(1),
		CornerRadius: radius,
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Background{}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				r := gtx.Dp(radius)
				defer clip.UniformRRect(image.Rectangle{Max: gtx.Constraints.Min}, r).Push(gtx.Ops).Pop()
				paint.Fill(gtx.Ops, colWhite)
				return layout.Dimensions{Size: gtx.Constraints.Min}
			},
			func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{
					Top: unit.Dp(10), Bottom: unit.Dp(10),
					Left: unit.Dp(12), Right: unit.Dp(12),
				}.Layout(gtx, content)
			},
		)
	})
}

func field(th *material.Theme, label string, ed *widget.Editor) layout.FlexChild {
	return layout.Rigid(func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.Caption(th, label)
				l.Color = colMuted
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				ed.Submit = false
				ed.SingleLine = true
				return layoutEditorBox(gtx, material.Editor(th, ed, label).Layout)
			}),
		)
	})
}

// multilineField is field for text with one entry per line
func multilineField(th *material.Theme, label string, ed *widget.Editor) layout.FlexChild {
	return layout.Rigid(func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.Caption(th, label)
				l.Color = colMuted
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				ed.Submit = false
				ed.SingleLine = false
				return layoutEditorBox(gtx, material.Editor(th, ed, label).Layout)
			}),
		)
	})
}

func passwordField(th *material.Theme, label string, ed *widget.Editor) layout.FlexChild {
	return layout.Rigid(func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.Caption(th, label)
				l.Color = colMuted
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				ed.Submit = false
				ed.SingleLine = true
				ed.Mask = '•'
				return layoutEditorBox(gtx, material.Editor(th, ed, label).Layout)
			}),
		)
	})
}

func spacer(h unit.Dp) layout.FlexChild {
	return layout.Rigid(layout.Spacer{Height: h}.Layout)
}
