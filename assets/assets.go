// Package assets holds the logo. Linux and macOS install it via desktop-entry;
// Windows links the same PNGs into .exe resources (cmd/sshr/*.syso).
package assets

import "embed"

// Icons are icons/sshr-<size>.png in IconSizes
//
//go:embed icons/*.png
var Icons embed.FS

// IconSizes are the sizes of Icons in pixels
var IconSizes = []int{16, 32, 48, 64, 128, 256, 512}
