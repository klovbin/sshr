package ui

import (
	"fmt"

	"gioui.org/layout"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

func layoutHosts(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	if len(s.hosts) == 0 {
		empty := material.Body1(th, s.t("list.empty"))
		empty.Color = colMuted
		empty.Alignment = text.Middle
		return layout.Center.Layout(gtx, empty.Layout)
	}
	return material.List(th, &s.list).Layout(gtx, len(s.hosts), func(gtx layout.Context, i int) layout.Dimensions {
		h := s.hosts[i]
		return layout.Inset{Top: unit.Dp(4), Bottom: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					t := material.Body1(th, h.Name)
					t.Font.Weight = 600
					return t.Layout(gtx)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					line := fmt.Sprintf("%s@%s:%d", h.User, h.Host, h.Port)
					sub := material.Caption(th, line)
					sub.Color = colMuted
					return sub.Layout(gtx)
				}),
			)
		})
	})
}

func layoutForm(gtx layout.Context, th *material.Theme, s *state) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		field(th, s.t("field.name"), &s.nameEd),
		spacer(10),
		field(th, s.t("field.host"), &s.hostEd),
		spacer(10),
		field(th, s.t("field.user"), &s.userEd),
		spacer(10),
		field(th, s.t("field.port"), &s.portEd),
	)
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
				return material.Editor(th, ed, label).Layout(gtx)
			}),
		)
	})
}

func spacer(h unit.Dp) layout.FlexChild {
	return layout.Rigid(layout.Spacer{Height: h}.Layout)
}
