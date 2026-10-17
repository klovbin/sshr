//go:build !windows

package desktop

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"sshr.dev/assets"
)

// icnsTypes maps icns OSTypes to PNG pixel size.
// See https://en.wikipedia.org/wiki/Apple_Icon_Image_format
var icnsTypes = []struct {
	typ  string
	size int
}{
	{"icp4", 16},
	{"icp5", 32},
	{"icp6", 64},
	{"ic07", 128},
	{"ic08", 256},
	{"ic09", 512},
	{"ic10", 1024}, // 512@2x — needed so 1Password / macOS do not upscale 16px mush
	{"ic11", 32},   // 16@2x
	{"ic12", 64},   // 32@2x
	{"ic13", 256},  // 128@2x
	{"ic14", 512},  // 256@2x
}

// icns builds the bundle icon from the PNGs. Prefer iconutil on macOS.
func icns() ([]byte, error) {
	if b, err := icnsNative(); err == nil && len(b) > 0 {
		return b, nil
	}
	return icnsFromPNGs()
}

// icnsFromPNGs packs PNGs into an icns container (fallback / non-darwin).
func icnsFromPNGs() ([]byte, error) {
	var body bytes.Buffer
	for _, t := range icnsTypes {
		png, err := assets.Icons.ReadFile(fmt.Sprintf("icons/sshr-%d.png", t.size))
		if err != nil {
			return nil, err
		}
		body.WriteString(t.typ)
		binary.Write(&body, binary.BigEndian, uint32(8+len(png)))
		body.Write(png)
	}
	var out bytes.Buffer
	out.WriteString("icns")
	binary.Write(&out, binary.BigEndian, uint32(8+body.Len()))
	out.Write(body.Bytes())
	return out.Bytes(), nil
}
