package desktop

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"sshr.dev/assets"
)

func dataHome() (string, error) {
	if d := os.Getenv("XDG_DATA_HOME"); filepath.IsAbs(d) {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share"), nil
}

// execQuote quotes a path for the Exec key of a desktop entry, inside
// quotes ", `, $ and \ get a backslash, then the string escape of every
// desktop entry value doubles each backslash and % is doubled so it is
// not a field code, a literal \ ends up as four of them, as the spec says
func execQuote(p string) string {
	q := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`", `$`, `\$`).Replace(p)
	q = strings.NewReplacer(`\`, `\\`, "\n", `\n`, "\t", `\t`, "\r", `\r`, `%`, `%%`).Replace(q)
	return `"` + q + `"`
}

// Install writes sshr.desktop and the icons, the window finds its icon by
// the app id, which Gio takes from the binary name, so both are named sshr
func Install() (string, error) {
	data, err := dataHome()
	if err != nil {
		return "", err
	}
	exe, err := executable()
	if err != nil {
		return "", err
	}
	if strings.ContainsAny(exe, "\n\r") {
		return "", fmt.Errorf("the path %q cannot go into a desktop entry", exe)
	}
	for _, n := range assets.IconSizes {
		png, err := assets.Icons.ReadFile(fmt.Sprintf("icons/sshr-%d.png", n))
		if err != nil {
			return "", err
		}
		if err := writeFile(filepath.Join(data, "icons", "hicolor", fmt.Sprintf("%dx%d", n, n), "apps", "sshr.png"), png, 0o644); err != nil {
			return "", err
		}
	}
	entry := filepath.Join(data, "applications", "sshr.desktop")
	body := "[Desktop Entry]\nType=Application\nName=sshr\nComment=SSH host manager\n" +
		"Exec=" + execQuote(exe) + "\nIcon=sshr\nStartupWMClass=sshr\nTerminal=false\nCategories=Network;RemoteAccess;\n"
	if err := writeFile(entry, []byte(body), 0o644); err != nil {
		return "", err
	}
	refresh(data)
	return entry, nil
}

// Remove deletes the entry and the icons Install wrote
func Remove() error {
	data, err := dataHome()
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(data, "applications", "sshr.desktop")); err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, n := range assets.IconSizes {
		os.Remove(filepath.Join(data, "icons", "hicolor", fmt.Sprintf("%dx%d", n, n), "apps", "sshr.png"))
	}
	refresh(data)
	return nil
}

// refresh updates the menu and icon caches where those tools exist, menus
// that watch the folders need neither
func refresh(data string) {
	if p, err := exec.LookPath("update-desktop-database"); err == nil {
		exec.Command(p, "-q", filepath.Join(data, "applications")).Run()
	}
	if p, err := exec.LookPath("gtk-update-icon-cache"); err == nil {
		exec.Command(p, "-q", "-t", filepath.Join(data, "icons", "hicolor")).Run()
	}
}
