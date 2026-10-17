package ui

import (
	"bytes"
	"image"
	_ "image/png"
	"sync"

	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"

	"sshr.dev/assets"
)

var (
	opIconOnce sync.Once
	opIconSrc  paint.ImageOp
)

func loadOPIcon() {
	opIconOnce.Do(func() {
		b, err := assets.Icons.ReadFile("icons/1password-128.png")
		if err != nil {
			return
		}
		img, _, err := image.Decode(bytes.NewReader(b))
		if err != nil {
			return
		}
		opIconSrc = paint.NewImageOp(img)
	})
}

// layoutOPMark draws the official 1Password app icon.
func layoutOPMark(gtx layout.Context, sizeDp unit.Dp) layout.Dimensions {
	loadOPIcon()
	sz := gtx.Dp(sizeDp)
	size := image.Pt(sz, sz)
	if opIconSrc.Size() == (image.Point{}) {
		return layout.Dimensions{Size: size}
	}
	defer clip.UniformRRect(image.Rectangle{Max: size}, gtx.Dp(unit.Dp(10))).Push(gtx.Ops).Pop()
	gtx.Constraints.Min = size
	gtx.Constraints.Max = size
	return widget.Image{
		Src:      opIconSrc,
		Fit:      widget.Cover,
		Position: layout.Center,
	}.Layout(gtx)
}
