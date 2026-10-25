package main

import (
	"fmt"
	"os"

	"sshr.dev/internal/app"
)

const certUsage = `Usage: sshr cert ca init --software [--replace]
       sshr cert ca show`

// cmdCert runs the short certificates: the authority of this machine, the
// hosts that log in with a certificate it signs, all of it local and off
// by default
func cmdCert(args []string) {
	switch {
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
