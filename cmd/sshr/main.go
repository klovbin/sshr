// The Windows icon and version info are resources in rsrc_windows_*.syso,
// go build links them in, regenerate them after the logo changes:
//
//go:generate go run github.com/tc-hib/go-winres@v0.3.3 simply --arch amd64,386,arm64 --manifest none --icon ../../assets/icons/sshr-512.png --product-name sshr --file-description "SSH host manager" --original-filename sshr.exe --out rsrc

package main

import (
	"errors"
	"fmt"
	"os"

	"sshr.dev/internal/app"
)

func main() {
	// every mode may hold the vault key or an opened secret, the askpass
	// call too, the memory is closed to other processes first
	if err := app.Harden(); errors.Is(err, app.ErrHardenSkipped) {
		fmt.Fprintf(os.Stderr, "sshr: warning: %v\n", err)
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "sshr: warning: memory of this process stays readable: %v\n", err)
	}
	// ssh runs sshr as SSH_ASKPASS for hosts with a saved password
	if app.IsAskpassCall(os.Args[1:]) {
		os.Exit(app.RunAskpass(os.Args[1]))
	}
	if len(os.Args) > 1 {
		runCLI(os.Args[1:])
		return
	}
	runGUI()
}
