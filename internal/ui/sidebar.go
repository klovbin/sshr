package ui

import (
	"image"

	"gioui.org/io/event"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// layoutSidebar content depends on screen: hosts hint + Add, or settings nav.
func layoutSidebar(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	w := int(s.sidebarW + 0.5)
	h := gtx.Constraints.Max.Y
	size := image.Pt(w, h)

	defer clip.Rect{Max: size}.Push(gtx.Ops).Pop()
	paint.Fill(gtx.Ops, colPanel)

	gtx.Constraints.Min = size
	gtx.Constraints.Max = size

	return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		switch s.screen {
		case screenSettings:
			return layoutSidebarSettings(gtx, th, s)
		default:
			return layoutSidebarHosts(gtx, th, s)
		}
	})
}

func layoutSidebarHosts(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			t := material.Body1(th, s.t("sidebar.hosts.title"))
			t.Font.Weight = 600
			t.Color = colFG
			return t.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Caption(th, s.t("sidebar.hosts.hint"))
			l.Color = colMuted
			return l.Layout(gtx)
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return layout.Dimensions{Size: gtx.Constraints.Min}
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			btn := material.Button(th, &s.addBtn, s.t("btn.add"))
			btn.Background = colAccent
			return btn.Layout(gtx)
		}),
	)
}

func layoutSidebarSettings(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return sidebarNavItem(gtx, th, &s.aboutBtn, s.t("sidebar.about"), s.settingsPane == settingsAbout)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return sidebarNavItem(gtx, th, &s.langNavBtn, s.t("settings.language"), s.settingsPane == settingsLanguage)
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return layout.Dimensions{Size: gtx.Constraints.Min}
		}),
	)
}

func sidebarNavItem(gtx layout.Context, th *material.Theme, btn *widget.Clickable, label string, active bool) layout.Dimensions {
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					l := material.Body1(th, label)
					l.Color = colMuted
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
	})
}

func drawSplitLine(gtx layout.Context, s *state, h int) {
	x := int(s.sidebarW + 0.5)
	col := colBorder
	if s.split.dragging {
		col = colAccent
	}
	paint.FillShape(gtx.Ops, col, clip.Rect{
		Min: image.Pt(x, 0),
		Max: image.Pt(x+1, h),
	}.Op())
}

// updateSplitDrag resizes the sidebar from pointer X in window coords
// (avoids layout-local jitter while dragging the splitter).
func updateSplitDrag(gtx layout.Context, s *state, minW, maxW float32, size image.Point) {
	pad := float32(gtx.Dp(unit.Dp(5)))

	x := int(s.sidebarW + 0.5)
	x0 := x - int(pad)
	if x0 < 0 {
		x0 = 0
	}
	x1 := x + int(pad)
	cursor := clip.Rect{Min: image.Pt(x0, 0), Max: image.Pt(x1, size.Y)}.Push(gtx.Ops)
	pointer.CursorColResize.Add(gtx.Ops)
	cursor.Pop()

	area := clip.Rect{Max: size}.Push(gtx.Ops)
	pass := pointer.PassOp{}.Push(gtx.Ops)
	event.Op(gtx.Ops, &s.split)

	for {
		ev, ok := gtx.Event(pointer.Filter{
			Target: &s.split,
			Kinds:  pointer.Press | pointer.Drag | pointer.Release | pointer.Cancel,
		})
		if !ok {
			break
		}
		e, ok := ev.(pointer.Event)
		if !ok {
			continue
		}
		switch e.Kind {
		case pointer.Press:
			if e.Buttons != pointer.ButtonPrimary && e.Source != pointer.Touch {
				continue
			}
			dx := e.Position.X - s.sidebarW
			if dx < 0 {
				dx = -dx
			}
			if dx > pad {
				continue
			}
			s.split.dragging = true
			s.split.pid = e.PointerID
			gtx.Execute(pointer.GrabCmd{Tag: &s.split, ID: e.PointerID})
			s.sidebarW = clamp(e.Position.X, minW, maxW)
		case pointer.Drag:
			if !s.split.dragging || e.PointerID != s.split.pid {
				continue
			}
			s.sidebarW = clamp(e.Position.X, minW, maxW)
		case pointer.Release, pointer.Cancel:
			if e.PointerID == s.split.pid {
				s.split.dragging = false
			}
		}
	}
	pass.Pop()
	area.Pop()
}
