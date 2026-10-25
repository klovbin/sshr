package syncclient

import (
	"errors"
	"net/http"
	"strconv"
)

// Backend is the store a sync goes through: it keeps encrypted blobs,
// device envelopes and signed manifests and replaces the manifest only
// when the counter is still the one the device saw, the client checks
// every signature itself, sshr-sync over HTTP is the one backend today
type Backend interface {
	// CreateAccount makes an account with dev as its first device and
	// returns the TokenResponse JSON
	CreateAccount(dev []byte) ([]byte, error)
	// Join asks to add dev to the account, TokenResponse JSON
	Join(dev []byte) ([]byte, error)
	// Devices lists the devices of the account, DeviceRecord JSON
	Devices() ([]byte, error)
	// Activate lets an approved device in
	Activate(id string) error
	// RemoveDevice takes a device out, ErrNotFound when it is gone
	RemoveDevice(id string) error
	// PutEnvelope stores the vault key of device id, ErrStaleEpoch when it
	// holds a newer one
	PutEnvelope(id string, env []byte) error
	// GetEnvelope reads the envelope of device id for epoch, or the newest
	// older one while that is not delivered yet, ErrNotFound when none,
	// sshr-sync keeps one envelope per device and answers with it
	GetEnvelope(id string, epoch int) ([]byte, error)
	PutBlob(hash string, blob []byte) error
	GetBlob(hash string) ([]byte, error)
	// Head is the newest signed manifest and its counter, ErrNotFound for
	// an account without one
	Head() (counter uint64, signed []byte, err error)
	// ManifestsAfter is a page of signed manifests after counter n,
	// ErrPending while this device waits for approval
	ManifestsAfter(n uint64) ([]byte, error)
	// PutManifest replaces the manifest only when its counter is still
	// expect, ErrCASLost when another device wrote first
	PutManifest(expect uint64, signed []byte) error
}

// The answers of a backend a sync acts on, a StatusError matches them
// with errors.Is
var (
	ErrNotFound   = errors.New("not found on the sync server")
	ErrCASLost    = errors.New("another device changed the account first")
	ErrStaleEpoch = errors.New("the device already has a newer vault key")
	ErrPending    = errors.New("this device waits for approval")
)

// StatusError is an answer of sshr-sync that is not a success, its text is
// the error of the server
type StatusError struct {
	Code int
	Body []byte
	// is is the error of the request this code means, if any
	is error
}

func (e *StatusError) Error() string { return serverError(e.Code, e.Body).Error() }

// Is matches the error the code means in the request that got it
func (e *StatusError) Is(target error) bool { return e.is != nil && target == e.is }

// httpBackend is sshr-sync, every request goes to the server and account
// of the state of c with its token
type httpBackend struct{ c *Client }

// want sends a request and turns every answer but ok into a StatusError,
// means names the error a code stands for in this request
func (h httpBackend) want(method, path string, body []byte, hdr map[string]string, ok int, means map[int]error) ([]byte, http.Header, error) {
	code, b, header, err := h.c.call(method, path, body, hdr)
	if err != nil {
		return nil, nil, err
	}
	if code != ok {
		return nil, nil, &StatusError{Code: code, Body: b, is: means[code]}
	}
	return b, header, nil
}

func (h httpBackend) CreateAccount(dev []byte) ([]byte, error) {
	b, _, err := h.want("POST", "!/v1/accounts", dev, nil, http.StatusCreated, nil)
	return b, err
}

func (h httpBackend) Join(dev []byte) ([]byte, error) {
	b, _, err := h.want("POST", "/join", dev, nil, http.StatusCreated, nil)
	return b, err
}

func (h httpBackend) Devices() ([]byte, error) {
	b, _, err := h.want("GET", "/devices", nil, nil, http.StatusOK, nil)
	return b, err
}

func (h httpBackend) Activate(id string) error {
	_, _, err := h.want("POST", "/devices/"+id+"/activate", nil, nil, http.StatusNoContent, nil)
	return err
}

func (h httpBackend) RemoveDevice(id string) error {
	_, _, err := h.want("DELETE", "/devices/"+id, nil, nil, http.StatusNoContent, map[int]error{http.StatusNotFound: ErrNotFound})
	return err
}

func (h httpBackend) PutEnvelope(id string, env []byte) error {
	_, _, err := h.want("PUT", "/envelopes/"+id, env, nil, http.StatusNoContent, map[int]error{http.StatusConflict: ErrStaleEpoch})
	return err
}

func (h httpBackend) GetEnvelope(id string, _ int) ([]byte, error) {
	b, _, err := h.want("GET", "/envelopes/"+id, nil, nil, http.StatusOK, map[int]error{http.StatusNotFound: ErrNotFound})
	return b, err
}

func (h httpBackend) PutBlob(hash string, blob []byte) error {
	_, _, err := h.want("PUT", "/blobs/"+hash, blob, nil, http.StatusNoContent, nil)
	return err
}

func (h httpBackend) GetBlob(hash string) ([]byte, error) {
	b, _, err := h.want("GET", "/blobs/"+hash, nil, nil, http.StatusOK, nil)
	return b, err
}

func (h httpBackend) Head() (uint64, []byte, error) {
	b, hdr, err := h.want("GET", "/manifest", nil, nil, http.StatusOK, map[int]error{http.StatusNotFound: ErrNotFound, http.StatusForbidden: ErrPending})
	if err != nil {
		return 0, nil, err
	}
	counter, _ := strconv.ParseUint(hdr.Get("ETag"), 10, 64)
	return counter, b, nil
}

func (h httpBackend) ManifestsAfter(n uint64) ([]byte, error) {
	b, _, err := h.want("GET", "/manifests?after="+strconv.FormatUint(n, 10), nil, nil, http.StatusOK, map[int]error{http.StatusForbidden: ErrPending})
	return b, err
}

func (h httpBackend) PutManifest(expect uint64, signed []byte) error {
	_, _, err := h.want("PUT", "/manifest", signed, map[string]string{"If-Match": strconv.FormatUint(expect, 10)}, http.StatusNoContent, map[int]error{http.StatusPreconditionFailed: ErrCASLost})
	return err
}

// backend is the store of c, sshr-sync unless a test or a later setting
// gives another
func (c *Client) backend() Backend {
	if c.Backend != nil {
		return c.Backend
	}
	return httpBackend{c}
}
