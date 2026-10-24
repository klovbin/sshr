package main

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

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
	res, err := store.RunRemote(h, "cat ~/.ssh/authorized_keys 2>/dev/null", nil, 30*time.Second)
	if err != nil {
		fatal(err)
	}
	if res.ExitCode == 255 {
		fatal(fmt.Errorf("ssh to %s failed: %s", h.Name, strings.TrimSpace(string(res.Stderr))))
	}
	sk, other := authorizedKeyTypes(res.Stdout)
	fmt.Printf("%s: %d key(s) on a hardware token, %d other key(s) in ~/.ssh/authorized_keys\n", h.Name, len(sk), len(other))
	for _, k := range other {
		fmt.Println("  not on a token: " + k)
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

// authorizedKeyTypes sorts the lines of an authorized_keys file into keys
// on a token and others, each as type, fingerprint and comment, options
// before a key (from=, command=) are read past, lines that are no key are
// left out
func authorizedKeyTypes(data []byte) (sk, other []string) {
	for len(data) > 0 {
		pub, comment, _, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			break
		}
		line := strings.TrimSpace(pub.Type() + " " + ssh.FingerprintSHA256(pub) + " " + comment)
		if strings.HasPrefix(pub.Type(), "sk-") {
			sk = append(sk, line)
		} else {
			other = append(other, line)
		}
		data = rest
	}
	return sk, other
}
