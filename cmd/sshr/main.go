package main

import "os"

func main() {
	if len(os.Args) > 1 {
		runCLI(os.Args[1:])
		return
	}
	runGUI()
}
