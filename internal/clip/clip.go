// Package clip reads images from and writes text to the system clipboard
// through the tools each OS already has, so the binary stays cgo-free:
// wl-paste/wl-copy on Wayland, xclip on X11, osascript/pbcopy on macOS,
// PowerShell/clip on Windows.
package clip

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ErrNoImage means the clipboard holds no image.
var ErrNoImage = errors.New("no image in clipboard")

// Image is clipboard picture data with a file extension matching its format.
type Image struct {
	Data []byte
	Ext  string // "png", "jpg", ...
}

// ReadImage returns the image currently in the clipboard.
func ReadImage() (*Image, error) {
	switch runtime.GOOS {
	case "darwin":
		return readDarwin()
	case "windows":
		return readWindows()
	default:
		if os.Getenv("WAYLAND_DISPLAY") != "" {
			return readWayland()
		}
		if os.Getenv("DISPLAY") != "" {
			return readX11()
		}
		return nil, errors.New("no Wayland or X11 session")
	}
}

// WriteText puts text into the clipboard.
func WriteText(s string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "windows":
		cmd = exec.Command("clip")
	default:
		if os.Getenv("WAYLAND_DISPLAY") != "" {
			cmd = exec.Command("wl-copy")
		} else {
			cmd = exec.Command("xclip", "-selection", "clipboard", "-in")
		}
	}
	cmd.Stdin = strings.NewReader(s)
	if out, err := cmd.CombinedOutput(); err != nil {
		return toolErr(cmd.Path, err, out)
	}
	return nil
}

// pickImageType chooses PNG when offered, otherwise the first image/* type.
func pickImageType(types []string) string {
	first := ""
	for _, t := range types {
		t = strings.TrimSpace(t)
		if t == "image/png" {
			return t
		}
		if first == "" && strings.HasPrefix(t, "image/") {
			first = t
		}
	}
	return first
}

func extFor(mime string) string {
	switch mime {
	case "image/jpeg":
		return "jpg"
	case "image/svg+xml":
		return "svg"
	}
	ext := strings.TrimPrefix(mime, "image/")
	if ext == "" || strings.ContainsAny(ext, "/+;. ") {
		return "png"
	}
	return ext
}

func readWayland() (*Image, error) {
	out, err := exec.Command("wl-paste", "--list-types").Output()
	if err != nil {
		if emptyClipboard(err) {
			return nil, ErrNoImage
		}
		return nil, toolErr("wl-paste", err, nil)
	}
	mime := pickImageType(strings.Split(string(out), "\n"))
	if mime == "" {
		return nil, ErrNoImage
	}
	data, err := exec.Command("wl-paste", "--no-newline", "--type", mime).Output()
	if err != nil {
		return nil, toolErr("wl-paste", err, nil)
	}
	return &Image{Data: data, Ext: extFor(mime)}, nil
}

func readX11() (*Image, error) {
	out, err := exec.Command("xclip", "-selection", "clipboard", "-target", "TARGETS", "-out").Output()
	if err != nil {
		if emptyClipboard(err) {
			return nil, ErrNoImage
		}
		return nil, toolErr("xclip", err, nil)
	}
	mime := pickImageType(strings.Split(string(out), "\n"))
	if mime == "" {
		return nil, ErrNoImage
	}
	data, err := exec.Command("xclip", "-selection", "clipboard", "-target", mime, "-out").Output()
	if err != nil {
		return nil, toolErr("xclip", err, nil)
	}
	return &Image{Data: data, Ext: extFor(mime)}, nil
}

// readDarwin asks AppleScript for the PNG flavour of the clipboard and has it
// write the bytes to a temp file, there is no stdout form for binary data
func readDarwin() (*Image, error) {
	return readViaTempFile(func(path string) *exec.Cmd {
		return exec.Command("osascript",
			"-e", "on run argv",
			"-e", "set f to open for access (POSIX file (item 1 of argv)) with write permission",
			"-e", "set eof f to 0",
			"-e", "try",
			"-e", "write (the clipboard as «class PNGf») to f",
			"-e", "on error",
			"-e", "close access f",
			"-e", "error number 3",
			"-e", "end try",
			"-e", "close access f",
			"-e", "end run",
			path)
	})
}

// readWindows uses System.Windows.Forms, which needs an STA thread, Windows
// PowerShell 5 runs STA by default and -STA makes it explicit
func readWindows() (*Image, error) {
	const script = `Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$i = [System.Windows.Forms.Clipboard]::GetImage()
if (-not $i) { exit 3 }
$i.Save($env:SSHR_CLIP_OUT, [System.Drawing.Imaging.ImageFormat]::Png)`
	return readViaTempFile(func(path string) *exec.Cmd {
		cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-STA", "-Command", script)
		cmd.Env = append(os.Environ(), "SSHR_CLIP_OUT="+path)
		return cmd
	})
}

// readViaTempFile runs a tool that saves the clipboard PNG to a path.
// Exit code 3 from the tool means "no image".
func readViaTempFile(mk func(path string) *exec.Cmd) (*Image, error) {
	dir, err := os.MkdirTemp("", "sshr-clip-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "clip.png")
	cmd := mk(path)
	if out, err := cmd.CombinedOutput(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 3 {
			return nil, ErrNoImage
		}
		if bytes.Contains(out, []byte("-1700")) { // AppleScript: can't coerce to PNGf
			return nil, ErrNoImage
		}
		return nil, toolErr(filepath.Base(cmd.Path), err, out)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, ErrNoImage
	}
	return &Image{Data: data, Ext: "png"}, nil
}

// emptyClipboard recognises "nothing copied" from wl-paste and "target not
// available" from xclip, which both exit non-zero on an empty clipboard.
func emptyClipboard(err error) bool {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return false
	}
	msg := string(ee.Stderr)
	return strings.Contains(msg, "Nothing is copied") || strings.Contains(msg, "not available")
}

func toolErr(tool string, err error, out []byte) error {
	if errors.Is(err, exec.ErrNotFound) {
		return fmt.Errorf("%s not found; install it to use the clipboard", filepath.Base(tool))
	}
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			msg = strings.TrimSpace(string(ee.Stderr))
		}
	}
	if msg != "" {
		return fmt.Errorf("%s: %s", filepath.Base(tool), lastLine(msg))
	}
	return fmt.Errorf("%s: %v", filepath.Base(tool), err)
}

func lastLine(s string) string {
	lines := strings.Split(s, "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
