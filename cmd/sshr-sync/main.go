// Command sshr-sync is the sync server of sshr, it stores only device
// public keys, encrypted blobs and signed manifests, it can lose data or
// refuse service but cannot read hosts or passwords
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"sshr.dev/internal/app"
	"sshr.dev/internal/syncserver"
)

func main() {
	listen := flag.String("listen", ":8443", "address to listen on")
	data := flag.String("data", "/var/lib/sshr-sync", "data directory")
	cert := flag.String("tls-cert", "", "TLS certificate file")
	key := flag.String("tls-key", "", "TLS key file")
	domain := flag.String("autocert", "", "get a Let's Encrypt certificate for this domain (needs port 443 or a TLS-ALPN path to it)")
	plain := flag.Bool("plain-http", false, "serve plain HTTP, allowed only on a loopback address behind a TLS reverse proxy")
	trustProxy := flag.Bool("trust-proxy", false, "count the join limit by the last X-Forwarded-For address of requests from this machine, for a reverse proxy that sets it")
	flag.Parse()

	if err := os.MkdirAll(*data, 0o700); err != nil {
		fail(err)
	}
	unlock, err := app.LockFile(filepath.Join(*data, ".lock"))
	if err != nil {
		fail(err)
	}
	defer unlock()
	srv, err := syncserver.New(*data)
	if err != nil {
		fail(err)
	}
	srv.TrustProxy = *trustProxy
	hs := &http.Server{
		Addr:              *listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	switch {
	case *plain:
		host, _, err := net.SplitHostPort(*listen)
		if ip := net.ParseIP(host); err != nil || host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			fail(fmt.Errorf("--plain-http only on 127.0.0.1, ::1 or localhost, put a TLS reverse proxy in front"))
		}
		fmt.Fprintf(os.Stderr, "sshr-sync: plain HTTP on %s, data in %s\n", *listen, *data)
		err = hs.ListenAndServe()
		fail(err)
	case *domain != "":
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*domain),
			Cache:      autocert.DirCache(filepath.Join(*data, "autocert")),
		}
		hs.TLSConfig = &tls.Config{GetCertificate: m.GetCertificate, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1", "acme-tls/1"}}
		fmt.Fprintf(os.Stderr, "sshr-sync: HTTPS for %s on %s, data in %s\n", *domain, *listen, *data)
		fail(hs.ListenAndServeTLS("", ""))
	case *cert != "" && *key != "":
		hs.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		fmt.Fprintf(os.Stderr, "sshr-sync: HTTPS on %s, data in %s\n", *listen, *data)
		fail(hs.ListenAndServeTLS(*cert, *key))
	default:
		fail(fmt.Errorf("give --tls-cert and --tls-key, --autocert <domain>, or --plain-http on a loopback address"))
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "sshr-sync: %v\n", err)
	os.Exit(1)
}
