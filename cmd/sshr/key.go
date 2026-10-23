package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"sshr.dev/internal/app"
)

const keyUsage = `Usage: sshr key new [name] [--no-passphrase]
       sshr key install <host> [public key file] [--use]`

// cmdKey makes a new key or puts a public key on a host
func cmdKey(store *app.Store, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, keyUsage)
		os.Exit(1)
	}
	switch args[0] {
	case "new":
		cmdKeyNew(args[1:])
	case "install":
		cmdKeyInstall(store, args[1:])
	default:
		fmt.Fprintln(os.Stderr, keyUsage)
		os.Exit(1)
	}
}

func cmdKeyNew(args []string) {
	name, noPass := app.DefaultKeyName, false
	for _, a := range args {
		switch {
		case a == "--no-passphrase":
			noPass = true
		case strings.HasPrefix(a, "-") || strings.ContainsAny(a, `/\`):
			fmt.Fprintln(os.Stderr, keyUsage)
			os.Exit(1)
		default:
			name = a
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fatal(err)
	}
	path := filepath.Join(home, ".ssh", name)
	host, _ := os.Hostname()
	kargs, err := app.KeygenArgs(path, "sshr@"+host, noPass)
	if err != nil {
		fatal(err)
	}
	cmd := exec.Command("ssh-keygen", kargs...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fatal(fmt.Errorf("ssh-keygen: %v", err))
	}
	fmt.Printf("New key %s, put it on a host with: sshr key install <host> %s.pub --use\n", path, path)
}

func cmdKeyInstall(store *app.Store, args []string) {
	use := false
	var rest []string
	for _, a := range args {
		if a == "--use" {
			use = true
			continue
		}
		rest = append(rest, a)
	}
	if len(rest) < 1 || len(rest) > 2 {
		fmt.Fprintln(os.Stderr, keyUsage)
		os.Exit(1)
	}
	h := findHost(store, "key install", rest[0])
	pub := ""
	if len(rest) == 2 {
		pub = rest[1]
	} else {
		home, _ := os.UserHomeDir()
		for _, n := range []string{app.DefaultKeyName, "id_ed25519", "id_ecdsa", "id_rsa"} {
			if p := filepath.Join(home, ".ssh", n+".pub"); fileExists(p) {
				pub = p
				break
			}
		}
		if pub == "" {
			fatal(fmt.Errorf("no public key in ~/.ssh, make one with sshr key new or name the .pub file"))
		}
	}
	line, err := app.ReadPublicKey(pub)
	if err != nil {
		fatal(err)
	}
	priv := strings.TrimSuffix(app.ExpandHome(pub), ".pub")
	if use {
		// checked before the install, a host is not switched to a key
		// file that is missing
		if err := app.CheckPrivateKey(priv); err != nil {
			fatal(fmt.Errorf("--use needs the private key next to %s: %v", pub, err))
		}
	}
	sshArgs, err := store.InstallKeyArgs(h)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("Installing %s on %s...\n", filepath.Base(pub), h.Name)
	cmd := exec.Command("ssh", sshArgs...)
	cmd.Stdin = strings.NewReader(line + "\n")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cleanup, err := app.AttachAuth(cmd, h)
	if err != nil {
		fatal(err)
	}
	err = cmd.Run()
	cleanup()
	if err != nil {
		fatal(fmt.Errorf("installing the key on %s failed: %v", h.Name, err))
	}
	if use {
		cur := *h
		cur.Key, cur.KeyMode, cur.Agent, cur.KeyRef, cur.KeyPub = priv, "", "", "", ""
		if cur.PasswordMode == app.PasswordAsk || cur.PasswordMode == app.PasswordSaved {
			cur.PasswordMode, cur.Password, cur.PasswordSealed, cur.PlainPassword = "", "", "", ""
		}
		if _, err := store.Update(h.ID, cur); err != nil {
			fatal(err)
		}
		fmt.Printf("%s now logs in with %s\n", h.Name, priv)
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
