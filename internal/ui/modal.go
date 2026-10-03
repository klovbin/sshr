package ui

import (
	"image"
	"image/color"

	"gioui.org/io/event"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	sshrapp "sshr.dev/internal/app"
)

// confirmModal is the delete confirmation overlay.
type confirmModal struct {
	open    bool
	title   string
	body    string
	hostID  string
	confirm widget.Clickable
	cancel  widget.Clickable
	scrim   struct{} // pointer tag: click outside closes
	card    struct{} // pointer tag: swallow presses so they don't hit scrim
}

// formModal is the add-host form overlay.
type formModal struct {
	open   bool
	err    string
	save   widget.Clickable
	cancel widget.Clickable
	scrim  struct{}
	card   struct{}
}

func (s *state) openDeleteConfirm(h sshrapp.Host) {
	s.form.close() // only one modal at a time
	s.modal.open = true
	s.modal.title = s.t("modal.delete.title")
	s.modal.body = s.t("modal.delete.body", h.Name)
	s.modal.hostID = h.ID
}

func (s *state) openAddForm() {
	s.modal.close()
	s.clearForm()
	s.form.err = ""
	s.form.open = true
	s.err = ""
}

func (m *confirmModal) close() {
	m.open = false
	m.hostID = ""
	m.title = ""
	m.body = ""
}

func (m *formModal) close() {
	m.open = false
	m.err = ""
}

func layoutModals(gtx layout.Context, th *material.Theme, s *state) {
	layoutConfirmModal(gtx, th, s)
	layoutFormModal(gtx, th, s)
}

// layoutModalCard draws a dimmed scrim + centered card.
// Scrim press closes; card eats presses so they don't fall through.
func layoutModalCard(gtx layout.Context, maxW unit.Dp, scrimTag, cardTag event.Tag, onScrimClose func(), content layout.Widget) {
	scrim := clip.Rect{Max: gtx.Constraints.Max}.Push(gtx.Ops)
	paint.Fill(gtx.Ops, color.NRGBA{R: 0x10, G: 0x12, B: 0x16, A: 0x99})
	event.Op(gtx.Ops, scrimTag)
	for {
		ev, ok := gtx.Event(pointer.Filter{
			Target: scrimTag,
			Kinds:  pointer.Press,
		})
		if !ok {
			break
		}
		if e, ok := ev.(pointer.Event); ok && e.Kind == pointer.Press {
			onScrimClose()
		}
	}
	scrim.Pop()

	layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		w := gtx.Dp(maxW)
		pad := gtx.Dp(unit.Dp(40))
		if gtx.Constraints.Max.X > pad && w > gtx.Constraints.Max.X-pad {
			w = gtx.Constraints.Max.X - pad
		}
		gtx.Constraints.Min.X = w
		gtx.Constraints.Max.X = w

		return widget.Border{
			Color:        colBorder,
			Width:        unit.Dp(1),
			CornerRadius: unit.Dp(14),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Background{}.Layout(gtx,
				func(gtx layout.Context) layout.Dimensions {
					r := gtx.Dp(unit.Dp(14))
					defer clip.UniformRRect(image.Rectangle{Max: gtx.Constraints.Min}, r).Push(gtx.Ops).Pop()
					paint.Fill(gtx.Ops, colWhite)
					event.Op(gtx.Ops, cardTag)
					for {
						_, ok := gtx.Event(pointer.Filter{
							Target: cardTag,
							Kinds:  pointer.Press,
						})
						if !ok {
							break
						}
					}
					return layout.Dimensions{Size: gtx.Constraints.Min}
				},
				func(gtx layout.Context) layout.Dimensions {
					return layout.UniformInset(unit.Dp(20)).Layout(gtx, content)
				},
			)
		})
	})
}

func layoutConfirmModal(gtx layout.Context, th *material.Theme, s *state) {
	if !s.modal.open {
		return
	}
	layoutModalCard(gtx, unit.Dp(360), &s.modal.scrim, &s.modal.card, s.modal.close, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				t := material.H6(th, s.modal.title)
				t.Color = colFG
				return t.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				b := material.Body2(th, s.modal.body)
				b.Color = colMuted
				return b.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(20)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Spacing: layout.SpaceEnd}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						btn := material.Button(th, &s.modal.cancel, s.t("btn.cancel"))
						btn.Background = colMuted
						btn.Inset = layout.Inset{
							Top: unit.Dp(8), Bottom: unit.Dp(8),
							Left: unit.Dp(14), Right: unit.Dp(14),
						}
						return btn.Layout(gtx)
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						btn := material.Button(th, &s.modal.confirm, s.t("btn.delete"))
						btn.Background = colErr
						btn.Inset = layout.Inset{
							Top: unit.Dp(8), Bottom: unit.Dp(8),
							Left: unit.Dp(14), Right: unit.Dp(14),
						}
						return btn.Layout(gtx)
					}),
				)
			}),
		)
	})
}

func layoutFormModal(gtx layout.Context, th *material.Theme, s *state) {
	if !s.form.open {
		return
	}
	layoutModalCard(gtx, unit.Dp(400), &s.form.scrim, &s.form.card, func() {
		s.form.close()
		s.clearForm()
	}, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				t := material.H6(th, s.t("modal.add.title"))
				t.Color = colFG
				return t.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layoutForm(gtx, th, s)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if s.form.err == "" {
					return layout.Dimensions{}
				}
				return layout.Inset{Top: unit.Dp(10)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					e := material.Caption(th, s.form.err)
					e.Color = colErr
					return e.Layout(gtx)
				})
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(18)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Spacing: layout.SpaceEnd}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						btn := material.Button(th, &s.form.cancel, s.t("btn.cancel"))
						btn.Background = colMuted
						btn.Inset = layout.Inset{
							Top: unit.Dp(8), Bottom: unit.Dp(8),
							Left: unit.Dp(14), Right: unit.Dp(14),
						}
						return btn.Layout(gtx)
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						btn := material.Button(th, &s.form.save, s.t("btn.save"))
						btn.Background = colAccent
						btn.Inset = layout.Inset{
							Top: unit.Dp(8), Bottom: unit.Dp(8),
							Left: unit.Dp(14), Right: unit.Dp(14),
						}
						return btn.Layout(gtx)
					}),
				)
			}),
		)
	})
}
