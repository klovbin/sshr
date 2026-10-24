package main

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"

	"sshr.dev/internal/app"
)

const hwkeyUsage = `Usage: sshr hwkey status
       sshr hwkey require <host>... | --all
       sshr hwkey off [<host>...]
       sshr hwkey check <host>`

// cmdHwkey sets which hosts connect only with a key on a FIDO token, the
// list lives in settings.json and never syncs
func cmdHwkey(store *app.Store, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, hwkeyUsage)
		os.Exit(1)
	}
	st, err := app.LoadSettings()
	if err != nil {
		fatal(err)
	}
	switch {
	case args[0] == "status" && len(args) == 1:
		hwkeyStatus(store, st)
		return
	case args[0] == "check" && len(args) == 2:
		hwkeyCheck(store, findHost(store, "hwkey check", args[1]))
		return
	case args[0] == "require" && len(args) == 2 && args[1] == "--all":
		st.HardwareKey = app.HardwareKeyAll
	case args[0] == "require" && len(args) > 1:
		for _, name := range args[1:] {
			st.RequireHardwareKey(findHost(store, "hwkey require", name).ID)
		}
	case args[0] == "off" && len(args) == 1:
		st.HardwareKey, st.HardwareKeyHosts = "", nil
	case args[0] == "off":
		for _, name := range args[1:] {
			st.ReleaseHardwareKey(findHost(store, "hwkey off", name).ID)
		}
	default:
		fmt.Fprintln(os.Stderr, hwkeyUsage)
		os.Exit(1)
	}
	if err := app.SaveSettings(st); err != nil {
		fatal(err)
	}
	hwkeyStatus(store, st)
}

// hwkeyStatus prints the mode and every host under it, with whether its
// login is a key on a token now, a host that is not would be refused at
// connect
func hwkeyStatus(store *app.Store, st app.Settings) {
	switch st.HardwareKey {
	case app.HardwareKeyAll:
		fmt.Println("every host connects only with a key on a hardware token")
	case app.HardwareKeyListed:
		fmt.Println("the hosts below connect only with a key on a hardware token")
	default:
		fmt.Println("no host needs a hardware key, sshr hwkey require <host> asks for one")
		return
	}
	list, err := store.List()
	if err != nil {
		fatal(err)
	}
	for i := range list {
		h := &list[i]
		if !st.HardwareKeyRequired(h.ID) {
			continue
		}
		state := "ready, its key is on a token"
		if err := app.CheckHardwareKey(h); err != nil {
			state = "refused at connect, " + err.Error()
		}
		fmt.Printf("  %s (%s): %s\n", h.Name, h.Dest(), state)
	}
	if st.HardwareKey == app.HardwareKeyListed {
		for _, id := range st.HardwareKeyHosts {
			if !slices.ContainsFunc(list, func(h app.Host) bool { return h.ID == id }) {
				fmt.Printf("  %s: no such host here, sshr hwkey off drops all\n", id)
			}
		}
	}
}

// hwkeyCheck reads ~/.ssh/authorized_keys on the host, logging in the way
// the host does, and lists the keys that are not on a token, with the
// lines of sshd_config that make the server take nothing else, it only
// reads, the server is left as it is
func hwkeyCheck(store *app.Store, h *app.Host) {
	res, err := store.RunRemote(h, authorizedKeysCommand, nil, 30*time.Second)
	if err != nil {
		fatal(err)
	}
	data, err := authorizedKeysOf(h.Name, res)
	if err != nil {
		fatal(err)
	}
	if data == nil {
		fmt.Printf("%s: there is no ~/.ssh/authorized_keys\n", h.Name)
	}
	sk, other := authorizedKeyTypes(data)
	fmt.Printf("%s: %d key(s) on a hardware token, %d other key(s) in ~/.ssh/authorized_keys\n", h.Name, len(sk), len(other))
	for _, k := range other {
		fmt.Println("  logs in without a token: " + k)
	}
	if len(sk) == 0 {
		fmt.Println("put a key on a token there first: sshr key new --sk, then sshr key install " + h.Name + " ~/.ssh/sshr_sk.pub --use")
	} else if len(other) > 0 {
		fmt.Println("remove the keys above from authorized_keys on the server, they log in without the token")
	}
	fmt.Println("with only keys on a token there, these lines in /etc/ssh/sshd_config make the server take nothing else:")
	for _, l := range []string{"PasswordAuthentication no", "KbdInteractiveAuthentication no", "AuthenticationMethods publickey", "PubkeyAuthOptions verify-required    (also ask the PIN of the token)"} {
		fmt.Println("  " + l)
	}
	fmt.Println("sshr changes nothing on the server, keep a second token or a console of the provider before you lock it down")
}

// authorizedKeysCommand prints authorized_keys of the login user, a file
// that is not there exits 3, so it is told apart from one that does not
// read
const authorizedKeysCommand = "test -e ~/.ssh/authorized_keys || exit 3; cat ~/.ssh/authorized_keys"

// authorizedKeysOf is the file authorizedKeysCommand read, nil when there
// is none, a read that failed is an error with what the server said, an
// empty answer must not pass for a file without keys
func authorizedKeysOf(name string, res *app.RemoteResult) ([]byte, error) {
	switch res.ExitCode {
	case 0:
		// the keys past the cut would be missing from the list the user
		// locks the server down by
		if res.Truncated {
			return nil, fmt.Errorf("~/.ssh/authorized_keys on %s is longer than sshr reads, the list would miss keys", name)
		}
		if res.Stdout == nil {
			return []byte{}, nil
		}
		return res.Stdout, nil
	case 3:
		return nil, nil
	case 255:
		return nil, fmt.Errorf("ssh to %s failed: %s", name, terminalSafe(strings.TrimSpace(string(res.Stderr))))
	}
	return nil, fmt.Errorf("reading ~/.ssh/authorized_keys on %s failed (exit %d): %s", name, res.ExitCode, terminalSafe(strings.TrimSpace(string(res.Stderr))))
}

// authorizedKeyTypes sorts the lines of an authorized_keys file into keys
// on a token and others, each as type, fingerprint and comment, options
// before a key (from=, command=) are read past, lines that are no key are
// left out, an sk key with no-touch-required logs in without a touch and
// a cert-authority line lets in any key it signed, both go to the others
// with the option named
func authorizedKeyTypes(data []byte) (sk, other []string) {
	for len(data) > 0 {
		pub, comment, options, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			break
		}
		line := strings.TrimSpace(pub.Type() + " " + ssh.FingerprintSHA256(pub) + " " + terminalSafe(comment))
		switch {
		case hasKeyOption(options, "cert-authority"):
			other = append(other, line+" (cert-authority, any key it signed logs in)")
		case !strings.HasPrefix(pub.Type(), "sk-"):
			other = append(other, line)
		case hasKeyOption(options, "no-touch-required"):
			other = append(other, line+" (no-touch-required, no touch of the token is asked)")
		default:
			sk = append(sk, line)
		}
		data = rest
	}
	return sk, other
}

// hasKeyOption tells whether an authorized_keys line carries the option
// name, sshd reads option names in any case
func hasKeyOption(options []string, name string) bool {
	for _, o := range options {
		if strings.EqualFold(o, name) {
			return true
		}
	}
	return false
}

// terminalSafe puts ? for control characters and the marks that turn
// text around, whoever can write authorized_keys on the server could
// otherwise move the cursor and hide lines of the list, the joiner of
// emoji stays
func terminalSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || unicode.In(r, unicode.Bidi_Control) {
			return '?'
		}
		return r
	}, s)
}
