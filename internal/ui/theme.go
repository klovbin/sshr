package ui

import (
	"image/color"
)

// Shared palette for the shell (light theme).
var (
	colAccent = color.NRGBA{R: 0x2f, G: 0x6f, B: 0xed, A: 0xff}
	colAccentSoft = color.NRGBA{R: 0x2f, G: 0x6f, B: 0xed, A: 0x12}
	colFG     = color.NRGBA{R: 0x1a, G: 0x1d, B: 0x23, A: 0xff}
	colMuted  = color.NRGBA{R: 0x6a, G: 0x70, B: 0x7a, A: 0xff}
	colMutedSoft = color.NRGBA{R: 0x9a, G: 0xa0, B: 0xaa, A: 0xff}
	colErr    = color.NRGBA{R: 0xc0, G: 0x3a, B: 0x2b, A: 0xff}
	colOK     = color.NRGBA{R: 0x1f, G: 0x8a, B: 0x4c, A: 0xff}
	colWarn   = color.NRGBA{R: 0xb7, G: 0x6e, B: 0x00, A: 0xff}
	colPanel  = color.NRGBA{R: 0xed, G: 0xf0, B: 0xf4, A: 0xff}
	colBorder = color.NRGBA{R: 0xd0, G: 0xd4, B: 0xda, A: 0xff}
	colField  = color.NRGBA{R: 0xf7, G: 0xf8, B: 0xfa, A: 0xff}
	// colInputBorder is darker so empty form fields stay visible
	colInputBorder = color.NRGBA{R: 0x8b, G: 0x92, B: 0x9a, A: 0xff}
	colWhite  = color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}
	colHover  = color.NRGBA{R: 0xf0, G: 0xf2, B: 0xf5, A: 0xff}
)

func clamp(v, min, max float32) float32 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
