package main

import (
	"fmt"
	"os"

	"sshr.dev/internal/app"
	"sshr.dev/internal/mcp"
)

// cmdMCP serves the MCP protocol on stdin and stdout, an AI assistant
// starts it, for example `claude mcp add sshr -- sshr mcp`
func cmdMCP(store *app.Store, args []string) {
	// stdin and stdout are the protocol, a vault passphrase comes only from
	// SSHR_ASKPASS
	app.NoTerminalPrompts = true
	st, _ := app.LoadSettings()
	opts := mcp.Options{AllowCommands: st.MCPCommands, Version: app.BuildVersion()}
	for _, a := range args {
		switch a {
		case "--allow-commands":
			opts.AllowCommands = true
		case "--no-commands":
			opts.AllowCommands = false
		default:
			fmt.Fprintln(os.Stderr, "Usage: sshr mcp [--allow-commands|--no-commands]")
			os.Exit(1)
		}
	}
	if err := mcp.Serve(os.Stdin, os.Stdout, store, opts); err != nil {
		fatal(err)
	}
}
