package desktop

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// bundlePath is the app bundle in the user's own Applications folder, no
// admin rights needed, Launchpad and Spotlight find it there
func bundlePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Applications", "sshr.app"), nil
}

const infoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key><string>sshr</string>
	<key>CFBundleIdentifier</key><string>dev.sshr.app</string>
	<key>CFBundleName</key><string>sshr</string>
	<key>CFBundleDisplayName</key><string>sshr</string>
	<key>CFBundleIconFile</key><string>sshr.icns</string>
	<key>CFBundleIconName</key><string>sshr</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
	<key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
`

// Install makes ~/Applications/sshr.app with a copy of the running sshr,
// the Dock shows the bundle icon only for a program inside the bundle, a
// link or a script that starts sshr elsewhere gets the generic icon, so
// the copy is renewed by running this again after an update
func Install() (string, error) {
	app, err := bundlePath()
	if err != nil {
		return "", err
	}
	exe, err := executable()
	if err != nil {
		return "", err
	}
	icon, err := icns()
	if err != nil {
		return "", err
	}
	bin, err := os.ReadFile(exe)
	if err != nil {
		return "", err
	}
	macOS := filepath.Join(app, "Contents", "MacOS")
	if err := writeFile(filepath.Join(macOS, "sshr"), bin, 0o755); err != nil {
		return "", err
	}
	// Never ship op inside the bundle: codesign --deep (or re-signing the
	// bundle) strips 1Password's Team ID and the desktop app refuses IPC.
	_ = os.Remove(filepath.Join(macOS, "op"))
	if err := writeFile(filepath.Join(app, "Contents", "Resources", "sshr.icns"), icon, 0o644); err != nil {
		return "", err
	}
	if err := writeFile(filepath.Join(app, "Contents", "Info.plist"), []byte(infoPlist), 0o644); err != nil {
		return "", err
	}
	// Ad-hoc sign the bundle only — do not use --deep (would break nested tools).
	if p, err := exec.LookPath("codesign"); err == nil {
		exec.Command(p, "--force", "--sign", "-", app).Run()
	}
	// Finder / LaunchServices cache icons by bundle mtime and registration.
	now := time.Now()
	os.Chtimes(app, now, now)
	os.Chtimes(filepath.Join(app, "Contents", "Info.plist"), now, now)
	os.Chtimes(filepath.Join(app, "Contents", "Resources", "sshr.icns"), now, now)
	if ls, err := exec.LookPath("lsregister"); err == nil {
		exec.Command(ls, "-f", app).Run()
	} else {
		// Common path when lsregister is not on PATH.
		exec.Command("/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister", "-f", app).Run()
	}
	return app, nil
}

// Remove deletes the app bundle, only when it is the one Install made
func Remove() error {
	app, err := bundlePath()
	if err != nil {
		return err
	}
	plist, err := os.ReadFile(filepath.Join(app, "Contents", "Info.plist"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !bytes.Contains(plist, []byte("<string>dev.sshr.app</string>")) {
		return fmt.Errorf("%s was not made by sshr, it is left as it is", app)
	}
	return os.RemoveAll(app)
}
