//go:build !nocgo

package main

import "sshr.dev/internal/ui"

func runGUI() {
	ui.Run()
}
