package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"sshr.dev/internal/app"
)

const keyUsage = `Usage: sshr key new [name] [--no-passphrase]
       sshr key new [name] --sk [--resident] [--verify-required]
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
	name, noPass, sk, resident, verify := "", false, false, false, false
	for _, a := range args {
		switch {
		case a == "--no-passphrase":
			noPass = true
		case a == "--sk":
			sk = true
		case a == "--resident":
			resident = true
		case a == "--verify-required":
			verify = true
		case strings.HasPrefix(a, "-") || strings.ContainsAny(a, `/\`):
			fmt.Fprintln(os.Stderr, keyUsage)
			os.Exit(1)
		default:
			name = a
		}
	}
	if (resident || verify) && !sk {
		fmt.Fprintln(os.Stderr, "sshr key new: --resident and --verify-required need --sk")
		os.Exit(1)
	}
	if name == "" {
		name = app.DefaultKeyName
		if sk {
			name = app.DefaultSKKeyName
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fatal(err)
	}
	path := filepath.Join(home, ".ssh", name)
	host, _ := os.Hostname()
	if sk {
		typ, err := makeSKKey(path, "sshr@"+host, resident, verify, runKeygen)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("New %s key %s, its private half stays on the token, put it on a host with: sshr key install <host> %s.pub --use\n", typ, path, path)
		return
	}
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

// makeSKKey makes a key on a FIDO token at path, Ed25519 first, ECDSA
// P-256 when the token does not make Ed25519 keys, run runs ssh-keygen with
// the arguments and copies its error output to w, it returns the type made
func makeSKKey(path, comment string, resident, verify bool, run func(args []string, w io.Writer) error) (string, error) {
	var last error
	for i, typ := range app.SKKeyTypes {
		kargs, err := app.SKKeygenArgs(path, comment, typ, resident, verify)
		if err != nil {
			return "", err
		}
		var errOut bytes.Buffer
		err = run(kargs, io.MultiWriter(os.Stderr, &errOut))
		if err == nil {
			return typ, nil
		}
		last = fmt.Errorf("ssh-keygen -t %s: %v", typ, err)
		// ssh-keygen says "feature not supported" for a missing key type and
		// for a token that cannot keep a resident key or check a PIN, with
		// those asked the next type fails the same way
		if app.SKUnsupported(errOut.String()) && (resident || verify) {
			last = fmt.Errorf("%v, the token may not support --resident or --verify-required, try without them", last)
			break
		}
		if i+1 < len(app.SKKeyTypes) && app.SKUnsupported(errOut.String()) {
			fmt.Fprintf(os.Stderr, "The token makes no %s keys, trying %s\n", typ, app.SKKeyTypes[i+1])
			continue
		}
		break
	}
	return "", last
}

// runKeygen runs ssh-keygen with the terminal of the user, it asks for the
// touch and the PIN
func runKeygen(args []string, w io.Writer) error {
	cmd := exec.Command("ssh-keygen", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, w
	return cmd.Run()
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
	cmd := app.SSHCommand(sshArgs...)
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
