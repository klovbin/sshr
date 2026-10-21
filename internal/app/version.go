package app

import "runtime/debug"

// Version is the sshr version, a release build sets it with
// -ldflags "-X sshr.dev/internal/app.Version=v1.2.3", otherwise it comes
// from the module version go install records, or "dev"
var Version = ""

// BuildVersion returns Version, or what the build recorded
func BuildVersion() string {
	if Version != "" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}
