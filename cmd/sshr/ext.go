package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"sshr.dev/internal/ext"
)

// cmdExt lists and removes the installed extensions
func cmdExt(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: sshr ext list | sshr ext remove <name>")
		os.Exit(1)
	}
	reg, err := ext.DefaultRegistry()
	if err != nil {
		fatal(err)
	}
	switch args[0] {
	case "list", "ls":
		if len(args) != 1 {
			fmt.Fprintln(os.Stderr, "Usage: sshr ext list")
			os.Exit(1)
		}
		extList(reg)
	case "remove", "rm":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "Usage: sshr ext remove <name>")
			os.Exit(1)
		}
		if err := reg.Remove(args[1]); err != nil {
			if errors.Is(err, ext.ErrNotInstalled) {
				fatal(fmt.Errorf("no extension %q is installed, sshr ext list shows them", args[1]))
			}
			fatal(err)
		}
		fmt.Printf("Removed extension %s\n", args[1])
	default:
		fmt.Fprintf(os.Stderr, "sshr ext: unknown command %q, use list or remove\n", args[0])
		os.Exit(1)
	}
}

func extList(reg *ext.Registry) {
	found, problems := reg.List()
	for _, p := range problems {
		fmt.Fprintf(os.Stderr, "sshr: %v\n", p)
	}
	if len(found) == 0 {
		fmt.Println("no extensions installed")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	for _, e := range found {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.Name, e.Version, strings.Join(e.Kinds, ","), e.Description)
	}
	w.Flush()
}

// runExtension runs the installed extension called name with args and exits
// with its exit code, it returns only when there is no such extension, so a
// built-in command always wins and an unknown word still gets the hint
func runExtension(name string, args []string) {
	reg, err := ext.DefaultRegistry()
	if err != nil {
		return
	}
	inst, err := reg.Find(name)
	if errors.Is(err, ext.ErrNotInstalled) {
		return
	}
	if err != nil {
		fatal(err)
	}
	bin, err := os.Executable()
	if err != nil {
		fatal(err)
	}
	cmd, err := inst.Command(ext.KindCommand, args, bin)
	if err != nil {
		fatal(err)
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		fatal(err)
	}
	stop := forwardSignals(cmd.Process)
	err = cmd.Wait()
	stop()
	os.Exit(exitCodeOf(err))
}

// exitCodeOf is the exit code of a finished child, 1 when it was killed by a
// signal and has none
func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var exit interface{ ExitCode() int }
	if errors.As(err, &exit) && exit.ExitCode() >= 0 {
		return exit.ExitCode()
	}
	return 1
}
