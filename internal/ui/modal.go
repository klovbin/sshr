package ui

import (
	"image"
	"image/color"

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
	open      bool
	title     string
	body      string
	hostID    string
	confirm   widget.Clickable
	cancel    widget.Clickable
	scrim     widget.Clickable // click outside card closes
	card      widget.Clickable // absorbs presses on the card
	blockScrim bool            // skip one scrim click after open
}

// formModal is the add-host form overlay.
type formModal struct {
	open       bool
	err        string
	save       widget.Clickable
	cancel     widget.Clickable
	scrim      widget.Clickable
	card       widget.Clickable
	blockScrim bool
}

func (s *state) openDeleteConfirm(h sshrapp.Host) {
	s.form.close() // only one modal at a time
	s.modal.open = true
	s.modal.blockScrim = true
	s.modal.title = s.t("modal.delete.title")
	s.modal.body = s.t("modal.delete.body", h.Name)
	s.modal.hostID = h.ID
}

func (s *state) openAddForm() {
	s.modal.close()
	s.clearForm()
	s.form.err = ""
	s.form.open = true
	s.form.blockScrim = true
	s.err = ""
}

func (m *confirmModal) close() {
	m.open = false
	m.hostID = ""
	m.title = ""
	m.body = ""
	m.blockScrim = false
}

func (m *formModal) close() {
	m.open = false
	m.err = ""
	m.blockScrim = false
}

func layoutModals(gtx layout.Context, th *material.Theme, s *state) {
	layoutConfirmModal(gtx, th, s)
	layoutFormModal(gtx, th, s)
}

// layoutModalCard draws scrim and card as Stack siblings.
// Card Clickable sits above the scrim so in-card presses never dismiss.
func layoutModalCard(gtx layout.Context, maxW unit.Dp, scrim, card *widget.Clickable, content layout.Widget) {
	layout.Stack{Alignment: layout.Center}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			return scrim.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				size := gtx.Constraints.Max
				defer clip.Rect{Max: size}.Push(gtx.Ops).Pop()
				paint.Fill(gtx.Ops, color.NRGBA{R: 0x10, G: 0x12, B: 0x16, A: 0x99})
				return layout.Dimensions{Size: size}
			})
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			w := gtx.Dp(maxW)
			pad := gtx.Dp(unit.Dp(40))
			if gtx.Constraints.Max.X > pad && w > gtx.Constraints.Max.X-pad {
				w = gtx.Constraints.Max.X - pad
			}
			gtx.Constraints.Min.X = w
			gtx.Constraints.Max.X = w

			return card.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
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
							return layout.Dimensions{Size: gtx.Constraints.Min}
						},
						func(gtx layout.Context) layout.Dimensions {
							return layout.UniformInset(unit.Dp(20)).Layout(gtx, content)
						},
					)
				})
			})
		}),
	)
}

func layoutConfirmModal(gtx layout.Context, th *material.Theme, s *state) {
	if !s.modal.open {
		return
	}
	layoutModalCard(gtx, unit.Dp(360), &s.modal.scrim, &s.modal.card, func(gtx layout.Context) layout.Dimensions {
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
	layoutModalCard(gtx, unit.Dp(400), &s.form.scrim, &s.form.card, func(gtx layout.Context) layout.Dimensions {
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
