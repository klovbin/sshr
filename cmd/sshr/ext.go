package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"text/tabwriter"

	"golang.org/x/term"

	"sshr.dev/internal/app"
	"sshr.dev/internal/ext"
)

// hiddenCommands are the commands of sshr that are not in sshr help
var hiddenCommands = []string{"op-accounts", app.ProxyCommandName, completeCommand, "--help", "-h"}

// isBuiltinCommand tells whether name is a command of sshr, an extension
// cannot take such a name, it would never run
func isBuiltinCommand(name string) bool {
	if findCommand(name) != nil {
		return true
	}
	for _, h := range hiddenCommands {
		if name == h {
			return true
		}
	}
	return false
}

// cmdExt installs, lists and removes extensions
func cmdExt(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: sshr ext install <git url or folder> [--yes] | sshr ext list | sshr ext remove <name>")
		os.Exit(1)
	}
	reg, err := ext.DefaultRegistry()
	if err != nil {
		fatal(err)
	}
	switch args[0] {
	case "install":
		extInstall(reg, args[1:])
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
		fmt.Fprintf(os.Stderr, "sshr ext: unknown command %q, use install, list or remove\n", args[0])
		os.Exit(1)
	}
}

// extInstall fetches an extension, shows what it is and what it will be
// allowed to do, and installs it after a yes
func extInstall(reg *ext.Registry, args []string) {
	yes := false
	var source string
	for _, a := range args {
		switch {
		case a == "--yes" || a == "-y":
			yes = true
		case source == "" && !strings.HasPrefix(a, "-"):
			source = a
		default:
			fmt.Fprintln(os.Stderr, "Usage: sshr ext install <git url or folder> [--yes]")
			os.Exit(1)
		}
	}
	if source == "" {
		fmt.Fprintln(os.Stderr, "Usage: sshr ext install <git url or folder> [--yes]")
		os.Exit(1)
	}
	st, err := ext.Prepare(source)
	if err != nil {
		fatal(err)
	}
	// fatal exits without running defers
	die := func(err error) {
		st.Discard()
		fatal(err)
	}
	defer st.Discard()
	if isBuiltinCommand(st.Name) {
		die(fmt.Errorf("%s is a command of sshr, an extension cannot have that name", st.Name))
	}
	argv, _ := st.Argv(runtime.GOOS)
	fmt.Printf("Extension %s %s\n", st.Name, st.Version)
	fmt.Printf("  does:   %s\n", st.Description)
	fmt.Printf("  kinds:  %s\n", strings.Join(st.Kinds, ", "))
	if argv != nil {
		fmt.Printf("  runs:   %s\n", shellLine(argv))
	} else {
		fmt.Printf("  runs:   nothing on %s, it has no command for this system\n", runtime.GOOS)
	}
	from := st.Lock.Source
	if st.Lock.Commit != "" {
		from += " at " + st.Lock.Commit
	}
	fmt.Printf("  from:   %s\n", from)
	fmt.Printf("  files:  %d, hash %s\n", st.Files, st.Lock.Tree[:16])
	if old, err := reg.Find(st.Name); err == nil {
		fmt.Printf("  it replaces version %s, installed from %s\n", old.Version, old.Lock.Source)
	}
	fmt.Println()
	fmt.Println("An extension runs as you and can do anything you can do. sshr gives it no password,")
	fmt.Println("key or secret reference, but it is a program on your machine, read its code first.")
	if !yes {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			die(errors.New("install asks for a yes and there is no terminal to ask in, add --yes"))
		}
		fmt.Print("Install it? [y/N]: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			fmt.Println("Not installed")
			return
		}
	}
	if err := reg.Install(st); err != nil {
		die(err)
	}
	fmt.Printf("Installed extension %s\n", st.Name)
	if st.Has(ext.KindCommand) {
		fmt.Printf("Run it with: sshr %s\n", st.Name)
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
