package ui

import (
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

func layoutFrame(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	iconBarW := float32(gtx.Dp(unit.Dp(56)))
	if s.sidebarW == 0 {
		s.sidebarW = float32(gtx.Dp(unit.Dp(200)))
	}
	minW := float32(gtx.Dp(unit.Dp(120)))
	maxW := float32(gtx.Constraints.Max.X) - float32(gtx.Dp(unit.Dp(280))) - iconBarW
	if maxW < minW {
		maxW = minW
	}

	updateSplitDrag(gtx, s, minW, maxW, gtx.Constraints.Max)
	s.sidebarW = clamp(s.sidebarW, minW, maxW)

	dims := layout.Flex{}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layoutSidebar(gtx, th, s)
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return layoutMain(gtx, th, s)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layoutIconBar(gtx, th, s)
		}),
	)

	drawSplitLine(gtx, s, dims.Size.Y)
	return dims
}

func layoutMain(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	return layout.UniformInset(unit.Dp(20)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layoutHeader(gtx, th, s)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if s.screen == screenSettings {
					return layout.Dimensions{}
				}
				msg := s.status
				c := colMutedSoft
				if s.err != "" {
					msg = s.err
					c = colErr
				}
				sub := material.Body2(th, msg)
				sub.Color = c
				return sub.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				switch s.screen {
				case screenForm:
					return layoutForm(gtx, th, s)
				case screenSettings:
					return layoutSettings(gtx, th, s)
				default:
					return layoutHosts(gtx, th, s)
				}
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layoutBottom(gtx, th, s)
			}),
		)
	})
}

func layoutHeader(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	title := s.t("app.title")
	if s.screen == screenSettings {
		title = s.t("settings.title")
	}
	t := material.H4(th, title)
	t.Color = colFG
	return t.Layout(gtx)
}

func layoutBottom(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	switch s.screen {
	case screenForm:
		return layout.Flex{Spacing: layout.SpaceBetween}.Layout(gtx,
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				btn := material.Button(th, &s.cancelBtn, s.t("btn.cancel"))
				btn.Background = colMuted
				return btn.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				btn := material.Button(th, &s.saveBtn, s.t("btn.save"))
				btn.Background = colAccent
				return btn.Layout(gtx)
			}),
		)
	case screenSettings:
		btn := material.Button(th, &s.backBtn, s.t("btn.back"))
		btn.Background = colMuted
		return btn.Layout(gtx)
	default:
		btn := material.Button(th, &s.addBtn, s.t("btn.add"))
		btn.Background = colAccent
		return btn.Layout(gtx)
	}
}
