package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"sshr.dev/internal/app"
)

const certUsage = `Usage: sshr cert ca init --software [--replace]
       sshr cert ca show
       sshr cert on <host> --principal <name>[,<name>...]
       sshr cert off <host>
       sshr cert status`

// cmdCert runs the short certificates: the authority of this machine, the
// hosts that log in with a certificate it signs, all of it local and off
// by default
func cmdCert(store *app.Store, args []string) {
	switch {
	case len(args) == 1 && args[0] == "status":
		certStatus(store)
	case len(args) == 2 && args[0] == "off":
		h := findHost(store, "cert off", args[1])
		st, err := app.LoadSettings()
		if err != nil {
			fatal(err)
		}
		st.DisableCert(h.ID)
		if err := app.SaveSettings(st); err != nil {
			fatal(err)
		}
		fmt.Printf("%s logs in as before, without a certificate\n", h.Name)
	case len(args) == 4 && args[0] == "on" && args[2] == "--principal":
		certOn(store, args[1], args[3])
	case len(args) >= 3 && args[0] == "ca" && args[1] == "init":
		certCAInit(args[2:])
	case len(args) == 2 && args[0] == "ca" && args[1] == "show":
		ca, err := app.LoadCertCA()
		if err != nil {
			fatal(err)
		}
		certCAShow(ca)
	default:
		fmt.Fprintln(os.Stderr, certUsage)
		os.Exit(1)
	}
}

// certOn lists a host for certificates, it needs the authority and says
// what the server needs
func certOn(store *app.Store, name, principals string) {
	ca, err := app.LoadCertCA()
	if err != nil {
		fatal(err)
	}
	h := findHost(store, "cert on", name)
	var list []string
	for _, p := range strings.Split(principals, ",") {
		if p = strings.TrimSpace(p); p != "" {
			if strings.ContainsAny(p, " \t\"'") {
				fatal(fmt.Errorf("principal %q: no spaces or quotes", p))
			}
			list = append(list, p)
		}
	}
	if len(list) == 0 {
		fatal(fmt.Errorf("give at least one principal, the account name on the server as its sshd knows it"))
	}
	st, err := app.LoadSettings()
	if err != nil {
		fatal(err)
	}
	if st.HardwareKeyRequired(h.ID) {
		fatal(fmt.Errorf("%s needs a hardware key, sshr does not sign on a token yet, take it off with sshr hwkey off %s first", h.Name, h.Name))
	}
	st.EnableCert(h.ID, app.CertTarget(h), list)
	if err := app.SaveSettings(st); err != nil {
		fatal(err)
	}
	fmt.Printf("%s now logs in only with a certificate for %s, valid %d minutes, signed at every connect\n", h.Name, strings.Join(list, ", "), st.CertMinutes())
	fmt.Println("Its saved password and key are not used while this is on, sshr cert off turns it back")
	fmt.Println("The server must trust the authority of this machine:")
	fmt.Printf("  %s\n", ca.Pub)
	fmt.Println("sshr cert ca show prints the lines for sshd_config or authorized_keys")
}

// certStatus prints the authority and every listed host
func certStatus(store *app.Store) {
	ca, err := app.LoadCertCA()
	switch {
	case errors.Is(err, app.ErrNoCA):
		fmt.Println("no certificate authority here, sshr cert ca init --software makes one")
	case err != nil:
		fatal(err)
	default:
		fmt.Printf("authority  %s %s\n", ca.Type, ca.Pub)
	}
	st, err := app.LoadSettings()
	if err != nil {
		fatal(err)
	}
	if len(st.CertHosts) == 0 {
		fmt.Println("no host logs in with a certificate, sshr cert on <host> --principal <name> lists one")
		return
	}
	fmt.Printf("certificates valid %d minutes\n", st.CertMinutes())
	list, err := store.List()
	if err != nil {
		fatal(err)
	}
	for i := range list {
		h := &list[i]
		if _, listed := st.CertHosts[h.ID]; !listed {
			continue
		}
		principals, _, err := st.CertFor(h.ID, app.CertTarget(h))
		if err != nil {
			fmt.Printf("  %-20s refused: %v\n", h.Name, err)
			continue
		}
		fmt.Printf("  %-20s %s\n", h.Name, strings.Join(principals, ", "))
	}
}

func certCAInit(args []string) {
	software, replace := false, false
	for _, a := range args {
		switch a {
		case "--software":
			software = true
		case "--replace":
			replace = true
		default:
			fmt.Fprintln(os.Stderr, certUsage)
			os.Exit(1)
		}
	}
	if !software {
		fmt.Fprintln(os.Stderr, certUsage)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "WARNING: the key of this authority is sealed with the vault key on this machine, whoever opens the vault here can log in to every server that trusts it, as any principal those servers allow")
	ca, err := app.InitSoftwareCA(replace)
	if err != nil {
		fatal(err)
	}
	fmt.Println("A certificate authority is set up on this machine")
	certCAShow(ca)
}

// certCAShow prints the key of the authority and what a server needs to
// trust it
func certCAShow(ca *app.CertCA) {
	kind := "software, the key sealed with the vault key"
	if ca.Type == "sk" {
		kind = "on a FIDO token, every login needs a touch"
	}
	fmt.Printf("authority  %s\nkey        %s\n\n", kind, ca.Pub)
	fmt.Println("To trust it on a server for every account (OpenSSH 5.4 or newer), as root:")
	fmt.Printf("  echo '%s' > /etc/ssh/sshr_ca.pub\n", ca.Pub)
	fmt.Println("  add the line  TrustedUserCAKeys /etc/ssh/sshr_ca.pub  to /etc/ssh/sshd_config and reload sshd")
	fmt.Println("  a certificate then logs in as each account it names as a principal")
	fmt.Println()
	fmt.Println("Or for one account only, without root, a line in its ~/.ssh/authorized_keys:")
	fmt.Printf("  cert-authority,principals=\"<name in the certificate>\" %s\n", ca.Pub)
	if ca.Type == "sk" {
		fmt.Println("\nA server needs OpenSSH 8.2 or newer to take a certificate signed on a token")
	}
}
