package ui

import (
	"image"

	"gioui.org/io/event"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

func layoutSidebar(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	w := int(s.sidebarW + 0.5)
	h := gtx.Constraints.Max.Y
	size := image.Pt(w, h)

	defer clip.Rect{Max: size}.Push(gtx.Ops).Pop()
	paint.Fill(gtx.Ops, colPanel)

	gtx.Constraints.Min = size
	gtx.Constraints.Max = size

	return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Dimensions{Size: gtx.Constraints.Min}
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
