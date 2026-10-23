package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"sshr.dev/internal/app"
)

const runUsage = "Usage: sshr run [-t <tag>]... [-j <parallel>] [--timeout <seconds>] [--json] [name or id...] -- <command>"

// cmdRun runs one command on several hosts at once, picked by name and by
// tag, each host's output is printed as a block when it finishes
func cmdRun(store *app.Store, args []string) {
	var tags, names []string
	parallel, timeout := 8, 60
	command := ""
	asJSON := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			command = strings.Join(args[i+1:], " ")
			i = len(args)
		case (a == "-t" || a == "--tag") && i+1 < len(args):
			i++
			tags = append(tags, app.SplitTags(args[i])...)
		case (a == "-j" || a == "--parallel") && i+1 < len(args):
			i++
			parallel = mustPositive(args[i], "-j")
		case a == "--timeout" && i+1 < len(args):
			i++
			timeout = mustPositive(args[i], "--timeout")
		case a == "--json":
			asJSON = true
		case strings.HasPrefix(a, "-"):
			fmt.Fprintln(os.Stderr, runUsage)
			os.Exit(1)
		default:
			names = append(names, a)
		}
	}
	if strings.TrimSpace(command) == "" || (len(tags) == 0 && len(names) == 0) {
		fmt.Fprintln(os.Stderr, runUsage)
		os.Exit(1)
	}
	hosts := pickHosts(store, names, tags)
	if len(hosts) == 0 {
		fatal(errors.New("no host has all of the tags " + strings.Join(tags, ", ")))
	}
	fmt.Fprintf(os.Stderr, "Running on %s: %s\n", plural(len(hosts), "host"), hostNames(hosts))

	var mu sync.Mutex
	var failed []string
	results := make([]runJSON, len(hosts))
	var wg sync.WaitGroup
	sem := make(chan struct{}, parallel)
	for i := range hosts {
		h, idx := &hosts[i], i
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			res, err := store.RunRemote(h, command, nil, time.Duration(timeout)*time.Second)
			mu.Lock()
			defer mu.Unlock()
			if asJSON {
				r := runJSON{Name: h.Name, ID: h.ID}
				if res != nil {
					r.ExitCode, r.Stdout, r.Stderr, r.Truncated = res.ExitCode, string(res.Stdout), string(res.Stderr), res.Truncated
				}
				if err != nil {
					r.Error = err.Error()
				}
				results[idx] = r
				if err != nil || res.ExitCode != 0 {
					failed = append(failed, h.Name)
				}
				return
			}
			switch {
			case errors.Is(err, app.ErrAsksPassword):
				fmt.Printf("== %s: skipped, it asks for its password every time\n", h.Name)
				failed = append(failed, h.Name)
			case err != nil:
				// a stopped command still has the output it printed so far
				fmt.Printf("== %s: %v\n", h.Name, err)
				if res != nil {
					writeOutput(os.Stdout, res)
				}
				failed = append(failed, h.Name)
			default:
				note := ""
				if res.Truncated {
					note = ", output cut at 64 KiB"
				}
				fmt.Printf("== %s (exit %d%s)\n", h.Name, res.ExitCode, note)
				writeOutput(os.Stdout, res)
				if res.ExitCode != 0 {
					failed = append(failed, h.Name)
				}
			}
		}()
	}
	wg.Wait()
	if asJSON {
		printJSON(results)
	}
	if len(failed) > 0 {
		fmt.Fprintf(os.Stderr, "%d of %d failed: %s\n", len(failed), len(hosts), strings.Join(failed, ", "))
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "%s, all succeeded\n", plural(len(hosts), "host"))
}

// writeOutput prints what the command wrote, ending with a newline
func writeOutput(w io.Writer, res *app.RemoteResult) {
	w.Write(res.Stdout)
	w.Write(res.Stderr)
	if n := len(res.Stdout) + len(res.Stderr); n > 0 && !strings.HasSuffix(string(res.Stdout)+string(res.Stderr), "\n") {
		fmt.Fprintln(w)
	}
}

// pickHosts returns the named hosts and the hosts having every tag, each
// once, in the order of the saved list
func pickHosts(store *app.Store, names, tags []string) []app.Host {
	want := map[string]bool{}
	for _, n := range names {
		want[findHost(store, "run", n).ID] = true
	}
	all, err := store.List()
	if err != nil {
		fatal(err)
	}
	var out []app.Host
	for _, h := range all {
		match := len(tags) > 0
		for _, t := range tags {
			match = match && h.HasTag(t)
		}
		if match || want[h.ID] {
			out = append(out, h)
		}
	}
	return out
}

func hostNames(hs []app.Host) string {
	names := make([]string, len(hs))
	for i, h := range hs {
		names[i] = h.Name
	}
	return strings.Join(names, ", ")
}

func mustPositive(v, flag string) int {
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		fatal(fmt.Errorf("%s takes a positive number, got %q", flag, v))
	}
	return n
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}
