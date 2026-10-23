package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// a client of the API socket from another user, or one the system could
// not name, is refused, a system that cannot ask lets the socket mode
// decide (#101)
func TestPeerGuard(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	for name, c := range map[string]struct {
		p    *peer
		want int
	}{
		"tcp":          {nil, 200},
		"same user":    {&peer{uid: os.Getuid()}, 200},
		"another user": {&peer{uid: os.Getuid() + 1}, 403},
		"no answer":    {&peer{uid: -1, err: errors.New("EINVAL")}, 403},
		"cannot ask":   {&peer{uid: -1, err: errPeerUnknown}, 200},
	} {
		req := httptest.NewRequest("GET", "/v1/hosts", nil)
		if c.p != nil {
			req = req.WithContext(context.WithValue(req.Context(), peerKey{}, *c.p))
		}
		rec := httptest.NewRecorder()
		peerGuard(ok).ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s = %d, want %d", name, rec.Code, c.want)
		}
	}
}
