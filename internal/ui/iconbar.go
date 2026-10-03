package ui

import (
	"image"

	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// layoutIconBar is the fixed right rail: hosts, then settings.
func layoutIconBar(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	const barW = unit.Dp(56)
	w := gtx.Dp(barW)
	h := gtx.Constraints.Max.Y
	size := image.Pt(w, h)

	defer clip.Rect{Max: size}.Push(gtx.Ops).Pop()
	paint.Fill(gtx.Ops, colPanel)

	paint.FillShape(gtx.Ops, colBorder, clip.Rect{
		Max: image.Pt(1, h),
	}.Op())

	gtx.Constraints.Min = size
	gtx.Constraints.Max = size

	return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
		layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return iconBarBtn(gtx, th, &s.hostsBtn, s.hostsIC,
				s.screen == screenList)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return iconBarBtn(gtx, th, &s.settingsBtn, s.settingsIC,
				s.screen == screenSettings)
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return layout.Dimensions{Size: gtx.Constraints.Min}
		}),
	)
}

func iconBarBtn(gtx layout.Context, th *material.Theme, btn *widget.Clickable, ic *widget.Icon, active bool) layout.Dimensions {
	if ic == nil {
		return layout.Dimensions{}
	}
	col := colMuted
	if active {
		col = colAccent
	}

	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						sz := gtx.Dp(unit.Dp(22))
						gtx.Constraints.Min = image.Pt(sz, sz)
						gtx.Constraints.Max = image.Pt(sz, sz)
						return ic.Layout(gtx, col)
					})
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					barW := gtx.Dp(unit.Dp(3))
					barH := gtx.Dp(unit.Dp(20))
					size := image.Pt(barW, barH)
					if !active {
						return layout.Dimensions{Size: image.Pt(barW, 0)}
					}
					defer clip.Rect{Max: size}.Push(gtx.Ops).Pop()
					paint.Fill(gtx.Ops, colAccent)
					return layout.Dimensions{Size: size}
				}),
			)
		})
	})
}
