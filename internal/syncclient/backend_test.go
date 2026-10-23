package syncclient

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// every answer of sshr-sync keeps the text it had and means the same
// error for each request (#128)
func TestHTTPBackendErrors(t *testing.T) {
	body := []byte(`{"error":"nope"}`)
	for _, c := range []struct {
		name string
		code int
		call func(Backend) error
		is   error
	}{
		{"remove gone", 404, func(b Backend) error { return b.RemoveDevice("d") }, ErrNotFound},
		{"remove other", 500, func(b Backend) error { return b.RemoveDevice("d") }, nil},
		{"envelope newer", 409, func(b Backend) error { return b.PutEnvelope("d", nil) }, ErrStaleEpoch},
		{"envelope missing", 404, func(b Backend) error { _, err := b.GetEnvelope("d"); return err }, ErrNotFound},
		{"blob missing", 404, func(b Backend) error { _, err := b.GetBlob("h"); return err }, nil},
		{"head none", 404, func(b Backend) error { _, _, err := b.Head(); return err }, ErrNotFound},
		{"history pending", 403, func(b Backend) error { _, err := b.ManifestsAfter(0); return err }, ErrPending},
		{"manifest lost", 412, func(b Backend) error { return b.PutManifest(1, nil) }, ErrCASLost},
		{"manifest blob missing", 409, func(b Backend) error { return b.PutManifest(1, nil) }, nil},
		{"join twice", 409, func(b Backend) error { _, err := b.Join(nil); return err }, nil},
		{"full", 507, func(b Backend) error { return b.PutBlob("h", nil) }, nil},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.code)
			w.Write(body)
		}))
		cl := &Client{st: &state{Server: srv.URL, Account: "acct", Token: "t"}}
		err := c.call(cl.backend())
		srv.Close()
		var se *StatusError
		if !errors.As(err, &se) || se.Code != c.code {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if err.Error() != serverError(c.code, body).Error() {
			t.Errorf("%s: text %q", c.name, err)
		}
		for _, sentinel := range []error{ErrNotFound, ErrCASLost, ErrStaleEpoch, ErrPending} {
			if errors.Is(err, sentinel) != (sentinel == c.is) {
				t.Errorf("%s: errors.Is(%v) = %v", c.name, sentinel, !(sentinel == c.is))
			}
		}
	}
}
