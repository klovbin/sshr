package app

import "fmt"

const redacted = "[redacted]"

// String prints the host for logs and errors with every secret and secret
// reference replaced, %v, %+v and %s of a Host or a *Host never show a
// password, a key or a sealed value
func (h Host) String() string {
	type plain Host
	return fmt.Sprintf("%+v", plain(h.redact()))
}

// GoString is String for %#v
func (h Host) GoString() string { return "app.Host" + h.String() }

func (h Host) redact() Host {
	for _, s := range []*string{&h.Password, &h.PasswordSealed, &h.PlainPassword, &h.PasswordRef,
		&h.KeyPassphrase, &h.KeySealed, &h.KeyRef} {
		if *s != "" {
			*s = redacted
		}
	}
	if h.KeyData != nil {
		h.KeyData = []byte(redacted)
	}
	// keys a newer sshr wrote may hold anything
	h.extra = nil
	return h
}
