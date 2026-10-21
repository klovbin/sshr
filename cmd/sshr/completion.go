package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"sshr.dev/internal/app"
)

// completeCommand is the hidden command the shell scripts call, it gets
// the words typed after sshr and the word under the cursor last
const completeCommand = "__complete"

// hostCommands take a host name as their first argument
var hostCommands = map[string]bool{
	"connect": true, "show": true, "rm": true, "ping": true, "tag": true, "send": true, "get": true,
	"forward": true, "tunnel": true, "close": true, "paste": true, "run": true,
}

var syncCommands = []string{"init", "invite", "join", "pending", "approve", "pull", "push", "status", "remove-device", "leave"}

var flagRe = regexp.MustCompile(`(?:^|[\s\[|])(--?[A-Za-z][A-Za-z-]*)`)

// complete returns the candidates for the word cur after the words typed
// before it, an empty list lets the shell complete file names
func complete(store *app.Store, words []string, cur string) []string {
	if len(words) == 0 {
		var out []string
		for _, c := range commands {
			out = append(out, c.name)
		}
		return filter(out, cur)
	}
	c := findCommand(words[0])
	if c == nil {
		return nil
	}
	prev := words[len(words)-1]
	switch {
	case c.name == "help" && len(words) == 1:
		return complete(store, nil, cur)
	case c.name == "sync" && len(words) == 1:
		return filter(syncCommands, cur)
	case c.name == "tag" && len(words) == 2:
		var out []string
		for _, t := range tagsOf(store, words[1]) {
			out = append(out, "-"+t)
		}
		for _, t := range tagsOf(store, "") {
			out = append(out, "+"+t)
		}
		return filter(out, cur)
	case strings.HasPrefix(cur, "-"):
		return filter(flagsOf(c), cur)
	case c.name == "run" && prev == "-t", c.name == "add" && prev == "-t", c.name == "list" && strings.HasPrefix(cur, "#"):
		return filter(tagsOf(store, ""), strings.TrimPrefix(cur, "#"))
	case c.name == "connect" && prev == "-F":
		return filter(append(forwardsOf(store, lastHost(words[1:len(words)-1])), "all"), cur)
	case c.name == "tunnel" && len(words) >= 2:
		return filter(forwardsOf(store, words[1]), cur)
	case c.name == "run" || hostCommands[c.name] && countArgs(words[1:]) == 0:
		return filter(savedNames(store), cur)
	}
	return nil
}

// countArgs counts the words that are not flags
func countArgs(words []string) int {
	n := 0
	for _, w := range words {
		if !strings.HasPrefix(w, "-") {
			n++
		}
	}
	return n
}

// lastHost is the last word that is neither a flag nor a flag's value
func lastHost(words []string) string {
	for i := len(words) - 1; i >= 0; i-- {
		if !strings.HasPrefix(words[i], "-") && (i == 0 || words[i-1] != "-F") {
			return words[i]
		}
	}
	return ""
}

func flagsOf(c *command) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range flagRe.FindAllStringSubmatch(c.usage+" "+c.details, -1) {
		if f := m[1]; !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

func savedNames(store *app.Store) []string {
	hosts, _ := store.List()
	var out []string
	for _, h := range hosts {
		out = append(out, h.Name)
	}
	sort.Strings(out)
	return out
}

// tagsOf returns the tags of one host, or of every host when query is empty
func tagsOf(store *app.Store, query string) []string {
	var hosts []app.Host
	if query == "" {
		hosts, _ = store.List()
	} else if h, err := store.Find(query); err == nil {
		hosts = []app.Host{*h}
	}
	seen := map[string]bool{}
	var out []string
	for _, h := range hosts {
		for _, t := range h.Tags {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	sort.Strings(out)
	return out
}

func forwardsOf(store *app.Store, query string) []string {
	h, err := store.Find(query)
	if err != nil {
		return nil
	}
	var out []string
	for _, f := range h.Forwards {
		out = append(out, f.Name)
	}
	return out
}

func filter(list []string, prefix string) []string {
	var out []string
	for _, s := range list {
		if strings.HasPrefix(s, prefix) {
			out = append(out, s)
		}
	}
	return out
}

func cmdComplete(store *app.Store, args []string) {
	if len(args) == 0 {
		return
	}
	for _, c := range complete(store, args[:len(args)-1], args[len(args)-1]) {
		fmt.Println(c)
	}
}

const bashCompletion = `# sshr completion for bash, source it or put it in
# ~/.local/share/bash-completion/completions/sshr
_sshr() {
	local IFS=$'\n'
	COMPREPLY=($(sshr __complete "${COMP_WORDS[@]:1:COMP_CWORD-1}" "${COMP_WORDS[COMP_CWORD]}" 2>/dev/null))
	[ ${#COMPREPLY[@]} -eq 0 ] && COMPREPLY=($(compgen -f -- "${COMP_WORDS[COMP_CWORD]}"))
}
complete -F _sshr sshr
`

const zshCompletion = `#compdef sshr
# sshr completion for zsh, add to ~/.zshrc: source <(sshr completion zsh)
_sshr() {
	local -a c
	c=("${(@f)$(sshr __complete "${(@)words[2,CURRENT-1]}" "${words[CURRENT]}" 2>/dev/null)}")
	if (( ${#c} )) && [[ -n $c[1] ]]; then compadd -a c; else _files; fi
}
compdef _sshr sshr
`

const fishCompletion = `# sshr completion for fish, put it in ~/.config/fish/completions/sshr.fish
function __sshr_complete
	set -l words (commandline -opc)
	sshr __complete $words[2..-1] (commandline -ct) 2>/dev/null
end
# file names only where sshr has nothing to offer, paths of send and get
complete -c sshr -f -n 'test -n "$(__sshr_complete)"' -a '(__sshr_complete)'
complete -c sshr -F -n 'test -z "$(__sshr_complete)"'
`

func cmdCompletion(args []string) {
	shell := ""
	if len(args) == 1 {
		shell = args[0]
	}
	switch shell {
	case "bash":
		fmt.Print(bashCompletion)
	case "zsh":
		fmt.Print(zshCompletion)
	case "fish":
		fmt.Print(fishCompletion)
	default:
		fmt.Fprintln(os.Stderr, "Usage: sshr completion bash|zsh|fish")
		os.Exit(1)
	}
}
