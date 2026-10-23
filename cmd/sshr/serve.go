package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"sshr.dev/internal/api"
	"sshr.dev/internal/app"
)

const serveUsage = "Usage: sshr serve [--listen unix:<path>|127.0.0.1:<port>] [--allow-commands|--no-commands]"

// cmdServe runs the REST API until Ctrl+C or SIGTERM
func cmdServe(store *app.Store, args []string) {
	st, _ := app.LoadSettings()
	opts := api.Options{AllowCommands: st.APICommands}
	listen := ""
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--listen" && i+1 < len(args):
			i++
			listen = args[i]
		case strings.HasPrefix(a, "--listen="):
			listen = strings.TrimPrefix(a, "--listen=")
		case a == "--allow-commands":
			opts.AllowCommands = true
		case a == "--no-commands":
			opts.AllowCommands = false
		default:
			fmt.Fprintln(os.Stderr, serveUsage)
			os.Exit(1)
		}
	}
	ln, where, err := apiListener(listen, &opts)
	if err != nil {
		fatal(err)
	}
	srv := api.New(store, opts)
	defer srv.Close()
	hs := &http.Server{Handler: srv}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		hs.Close()
	}()
	fmt.Fprintf(os.Stderr, "sshr serve: listening on %s, Ctrl+C stops\n", where)
	if opts.AllowCommands {
		fmt.Fprintln(os.Stderr, "sshr serve: commands are allowed (POST /v1/hosts/{host}/run)")
	}
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal(err)
	}
}

// apiListener opens the socket of the API, a unix socket in the 0700
// ControlDir by default, any program of this user can reach it and no
// one else, a TCP address must be a loopback one and gets a token, any
// local program could reach the port otherwise
func apiListener(listen string, opts *api.Options) (net.Listener, string, error) {
	if listen == "" || strings.HasPrefix(listen, "unix:") {
		path := strings.TrimPrefix(listen, "unix:")
		if path == "" {
			dir, err := app.ControlDir()
			if err != nil {
				return nil, "", err
			}
			path = filepath.Join(dir, "api.sock")
		}
		// a socket left by a server that crashed would block the new one
		if c, err := net.Dial("unix", path); err == nil {
			c.Close()
			return nil, "", fmt.Errorf("another sshr serve is already listening on %s", path)
		}
		if err := removeStaleSocket(path); err != nil {
			return nil, "", err
		}
		ln, err := net.Listen("unix", path)
		if err != nil {
			return nil, "", err
		}
		os.Chmod(path, 0o600)
		return ln, "unix:" + path, nil
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, "", fmt.Errorf("--listen %q: %v", listen, err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, "", fmt.Errorf("--listen %q: only 127.0.0.1, ::1 or localhost, the API is not for the network", listen)
	}
	token, path, err := apiToken()
	if err != nil {
		return nil, "", err
	}
	opts.Token = token
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, "", err
	}
	fmt.Fprintf(os.Stderr, "sshr serve: send \"Authorization: Bearer <token>\", the token is in %s\n", path)
	return ln, "http://" + ln.Addr().String(), nil
}

// apiToken reads ~/.sshr/api-token or creates it (0600)
func apiToken() (token, path string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	path = filepath.Join(home, ".sshr", "api-token")
	// a read during a rewrite by another sshr serve fails on Windows, a new
	// token here would leave that one with a stale token
	if b, err := app.ReadFileShared(path); err == nil && len(strings.TrimSpace(string(b))) >= 32 {
		return strings.TrimSpace(string(b)), path, nil
	}
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(buf[:])
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", "", err
	}
	return token, path, app.WriteFileAtomic(path, []byte(token+"\n"), 0o600)
}

// removeStaleSocket removes a socket left at path, anything else that is
// there stays and is an error
func removeStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket, choose another path", path)
	}
	return os.Remove(path)
}
