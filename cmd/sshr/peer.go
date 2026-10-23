package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"syscall"
)

// errPeerUnknown means this system cannot tell who is at the other end of
// a unix socket
var errPeerUnknown = errors.New("the peer of a unix socket is not known here")

type peerKey struct{}

// peer is what the API socket knows about a client
type peer struct {
	uid int
	err error
}

func unixRaw(c net.Conn) (syscall.RawConn, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil, errors.New("not a unix socket")
	}
	return uc.SyscallConn()
}

// peerContext records the uid of a client of the unix socket, ConnContext
// of the http.Server
func peerContext(ctx context.Context, c net.Conn) context.Context {
	if _, ok := c.(*net.UnixConn); !ok {
		return ctx
	}
	uid, err := peerUID(c)
	return context.WithValue(ctx, peerKey{}, peer{uid, err})
}

// peerGuard refuses a client of the unix socket that runs as another user,
// the socket is 0600 already, this holds when a custom path or a chmod
// that did not happen leaves it open, a peer that cannot be asked on a
// system that can ask is refused too
func peerGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := r.Context().Value(peerKey{}).(peer); ok {
			switch {
			case errors.Is(p.err, errPeerUnknown):
			case p.err != nil:
				http.Error(w, `{"error":"cannot tell who is connecting: `+p.err.Error()+`"}`, http.StatusForbidden)
				return
			case p.uid != os.Getuid():
				http.Error(w, `{"error":"connect as the user who runs sshr serve"}`, http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// peerName names the client of a request for the audit log, the uid on the
// unix socket, the address on TCP
func peerName(r *http.Request) string {
	if p, ok := r.Context().Value(peerKey{}).(peer); ok && p.err == nil {
		return fmt.Sprintf("uid %d", p.uid)
	}
	return r.RemoteAddr
}
