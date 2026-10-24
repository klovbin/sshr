package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"sshr.dev/internal/app"
	"sshr.dev/internal/davstore"
	"sshr.dev/internal/s3store"
	"sshr.dev/internal/syncclient"
)

// storeFlags are the flags of sshr sync init and join that put the account
// in a bucket or a WebDAV folder instead of on sshr-sync
type storeFlags struct {
	backend string
	s3      s3store.Config
	dav     davstore.Config
	// given says that one of them was on the command line, s3Given and
	// davGiven that one of the S3 or of the WebDAV ones was
	given, s3Given, davGiven bool
}

// flagValue is the value after the flag at args[i], a missing one or the
// next flag is an error, --bucket --key-id K must not make a bucket named
// --key-id
func flagValue(args []string, i *int) (string, error) {
	if *i+1 >= len(args) || strings.HasPrefix(args[*i+1], "-") {
		return "", fmt.Errorf("%s needs a value", args[*i])
	}
	*i++
	return args[*i], nil
}

// take reads the flag at args[i] and its value, it says whether it was one
// of the store flags
func (f *storeFlags) take(args []string, i *int) (bool, error) {
	s3 := map[string]*string{
		"--endpoint": &f.s3.Endpoint, "--bucket": &f.s3.Bucket,
		"--prefix": &f.s3.Prefix, "--region": &f.s3.Region, "--key-id": &f.s3.KeyID,
	}
	dav := map[string]*string{"--url": &f.dav.URL, "--user": &f.dav.User}
	a := args[*i]
	dst := s3[a]
	switch {
	case a == "--backend":
		dst = &f.backend
	case dst != nil:
		f.s3Given = true
	case dav[a] != nil:
		dst, f.davGiven = dav[a], true
	default:
		return false, nil
	}
	v, err := flagValue(args, i)
	if err != nil {
		return true, err
	}
	*dst, f.given = v, true
	return true, nil
}

// davPassword is the password of the WebDAV user, from
// SSHR_WEBDAV_PASSWORD or asked on the terminal, it never goes on the
// command line
func davPassword(user string) (string, error) {
	if s := os.Getenv("SSHR_WEBDAV_PASSWORD"); s != "" {
		return s, nil
	}
	s, err := app.AskTerminal("WebDAV password for " + user + ": ")
	if err != nil {
		return "", fmt.Errorf("no WebDAV password, set SSHR_WEBDAV_PASSWORD or run in a terminal: %v", err)
	}
	if s == "" {
		return "", errors.New("no WebDAV password")
	}
	return s, nil
}

// s3Secret is the secret key of the bucket, from SSHR_S3_SECRET or asked
// on the terminal, it never goes on the command line
func s3Secret(keyID string) (string, error) {
	if s := os.Getenv("SSHR_S3_SECRET"); s != "" {
		return s, nil
	}
	s, err := app.AskTerminal("S3 secret key for " + keyID + ": ")
	if err != nil {
		return "", fmt.Errorf("no S3 secret key, set SSHR_S3_SECRET or run in a terminal: %v", err)
	}
	if s == "" {
		return "", errors.New("no S3 secret key")
	}
	return s, nil
}

// setup opens the bucket of the flags for a new account or a join, checks
// that it refuses a second create and returns the address the state keeps,
// without --backend it leaves c on sshr-sync at server
func (f *storeFlags) setup(c *syncclient.Client, server string) (string, error) {
	switch f.backend {
	case "":
		if f.s3Given {
			return "", errors.New("--endpoint, --bucket, --prefix, --region and --key-id need --backend s3")
		}
		if f.davGiven {
			return "", errors.New("--url and --user need --backend webdav")
		}
		return server, nil
	case "s3":
		if f.davGiven {
			return "", errors.New("--url and --user are for --backend webdav")
		}
	case "webdav":
		if f.s3Given {
			return "", errors.New("--endpoint, --bucket, --prefix, --region and --key-id are for --backend s3")
		}
		if server != "" {
			return "", errors.New("--server is for sshr-sync, a WebDAV account takes --url and --user")
		}
		return f.setupDAV(c)
	default:
		return "", fmt.Errorf("unknown sync backend %q, there are s3 and webdav", f.backend)
	}
	if server != "" {
		return "", errors.New("--server is for sshr-sync, an S3 account takes --endpoint and --bucket")
	}
	if f.s3.Endpoint == "" || f.s3.Bucket == "" || f.s3.KeyID == "" {
		return "", errors.New("an S3 account needs --endpoint <url> --bucket <name> --key-id <id>")
	}
	if err := s3store.CheckEndpoint(f.s3.Endpoint); err != nil {
		return "", err
	}
	secret, err := s3Secret(f.s3.KeyID)
	if err != nil {
		return "", err
	}
	store, err := s3store.New(f.s3, secret, nil)
	if err != nil {
		return "", err
	}
	if err := syncclient.ProbeCreate(store); err != nil {
		return "", err
	}
	cfg, err := json.Marshal(f.s3)
	if err != nil {
		return "", err
	}
	c.Backend = syncclient.ObjectBackend{Store: store}
	c.BackendRef = &syncclient.BackendRef{Kind: "s3", Config: cfg}
	c.StoreSecret = secret
	return s3Address(f.s3), nil
}

// setupDAV opens the WebDAV folder of the flags, checks that it refuses a
// second create and returns the address the state keeps
func (f *storeFlags) setupDAV(c *syncclient.Client) (string, error) {
	if f.dav.URL == "" || f.dav.User == "" {
		return "", errors.New("a WebDAV account needs --url <folder address> --user <name>")
	}
	if err := syncclient.CheckStoreURL("WebDAV address", f.dav.URL); err != nil {
		return "", err
	}
	secret, err := davPassword(f.dav.User)
	if err != nil {
		return "", err
	}
	store, err := davstore.New(f.dav, secret, nil)
	if err != nil {
		return "", err
	}
	if err := syncclient.ProbeCreate(store); err != nil {
		return "", err
	}
	cfg, err := json.Marshal(f.dav)
	if err != nil {
		return "", err
	}
	c.Backend = syncclient.ObjectBackend{Store: store}
	c.BackendRef = &syncclient.BackendRef{Kind: "webdav", Config: cfg}
	c.StoreSecret = secret
	return "webdav " + f.dav.URL, nil
}

// replaceKey puts a new key of the bucket of this account into the state
// and the keychain, only --key-id may change, the bucket stays
func (f *storeFlags) replaceKey(c *syncclient.Client) error {
	if f.backend != "" || f.s3.Endpoint != "" || f.s3.Bucket != "" || f.s3.Prefix != "" || f.s3.Region != "" || f.dav.URL != "" {
		return errors.New("sshr sync store-key takes only --key-id for a bucket or --user for WebDAV, the place of the account stays")
	}
	ref, err := c.StoreRef()
	if err != nil {
		return err
	}
	if ref == nil {
		return errors.New("this account syncs through sshr-sync, it has no store key")
	}
	switch ref.Kind {
	case "webdav":
		return f.replaceDAVPassword(c, *ref)
	case "s3":
	default:
		return fmt.Errorf("this sshr cannot open a sync store of kind %q", ref.Kind)
	}
	if f.davGiven {
		return errors.New("--user is for a WebDAV account, a bucket takes --key-id")
	}
	if f.s3.KeyID == "" {
		return errors.New("sshr sync store-key --key-id <id>")
	}
	var cfg s3store.Config
	if err := json.Unmarshal(ref.Config, &cfg); err != nil {
		return fmt.Errorf("the S3 settings in the sync state: %v", err)
	}
	cfg.KeyID = f.s3.KeyID
	secret, err := s3Secret(cfg.KeyID)
	if err != nil {
		return err
	}
	store, err := s3store.New(cfg, secret, nil)
	if err != nil {
		return err
	}
	if err := syncclient.ProbeCreate(store); err != nil {
		return err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return c.ReplaceStoreKey(*ref, syncclient.BackendRef{Kind: "s3", Config: raw}, secret, syncclient.ObjectBackend{Store: store})
}

// replaceDAVPassword puts a new password, and a new user if --user names
// one, of the WebDAV folder of this account into the state and the keychain
func (f *storeFlags) replaceDAVPassword(c *syncclient.Client, ref syncclient.BackendRef) error {
	if f.s3Given {
		return errors.New("--key-id is for a bucket, a WebDAV account takes --user or nothing")
	}
	var cfg davstore.Config
	if err := json.Unmarshal(ref.Config, &cfg); err != nil {
		return fmt.Errorf("the WebDAV settings in the sync state: %v", err)
	}
	if f.dav.User != "" {
		cfg.User = f.dav.User
	}
	secret, err := davPassword(cfg.User)
	if err != nil {
		return err
	}
	store, err := davstore.New(cfg, secret, nil)
	if err != nil {
		return err
	}
	if err := syncclient.ProbeCreate(store); err != nil {
		return err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return c.ReplaceStoreKey(ref, syncclient.BackendRef{Kind: "webdav", Config: raw}, secret, syncclient.ObjectBackend{Store: store})
}

// s3Address names the bucket in the status, it is not dialed
func s3Address(cfg s3store.Config) string {
	return "s3 " + strings.TrimRight(cfg.Endpoint, "/") + " " + strings.Trim(cfg.Bucket+"/"+cfg.Prefix, "/")
}

// openStore opens the store a sync state names on later runs
func openStore(ref syncclient.BackendRef, secret string) (syncclient.Backend, error) {
	if ref.Kind == "webdav" {
		var cfg davstore.Config
		if err := json.Unmarshal(ref.Config, &cfg); err != nil {
			return nil, fmt.Errorf("the WebDAV settings in the sync state: %v", err)
		}
		store, err := davstore.New(cfg, secret, nil)
		if err != nil {
			return nil, err
		}
		return syncclient.ObjectBackend{Store: store}, nil
	}
	if ref.Kind != "s3" {
		return nil, fmt.Errorf("this sshr cannot open a sync store of kind %q", ref.Kind)
	}
	var cfg s3store.Config
	if err := json.Unmarshal(ref.Config, &cfg); err != nil {
		return nil, fmt.Errorf("the S3 settings in the sync state: %v", err)
	}
	store, err := s3store.New(cfg, secret, nil)
	if err != nil {
		return nil, err
	}
	return syncclient.ObjectBackend{Store: store}, nil
}

// joinFlags are the flags a new device passes to sshr sync join for an
// account at server or in the store ref, the secret key travels apart
func joinFlags(server string, ref *syncclient.BackendRef) (string, error) {
	if ref == nil {
		return "--server " + server, nil
	}
	if ref.Kind == "webdav" {
		var cfg davstore.Config
		if err := json.Unmarshal(ref.Config, &cfg); err != nil {
			return "", fmt.Errorf("the WebDAV settings in the sync state: %v", err)
		}
		return "--backend webdav --url " + shellQuote(cfg.URL) + " --user " + shellQuote(cfg.User), nil
	}
	if ref.Kind != "s3" {
		return "", fmt.Errorf("this sshr cannot open a sync store of kind %q", ref.Kind)
	}
	var cfg s3store.Config
	if err := json.Unmarshal(ref.Config, &cfg); err != nil {
		return "", fmt.Errorf("the S3 settings in the sync state: %v", err)
	}
	out := "--backend s3 --endpoint " + shellQuote(cfg.Endpoint) + " --bucket " + shellQuote(cfg.Bucket)
	if cfg.Prefix != "" {
		out += " --prefix " + shellQuote(cfg.Prefix)
	}
	if cfg.Region != "" {
		out += " --region " + shellQuote(cfg.Region)
	}
	return out + " --key-id " + shellQuote(cfg.KeyID), nil
}

// shellQuote puts a value of the join line in single quotes when it holds
// anything a shell would split or expand, a user "John Doe" stays one
// argument when the line is copied
func shellQuote(v string) string {
	safe := v != ""
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._~:/@%+=-,", r)) {
			safe = false
			break
		}
	}
	if safe {
		return v
	}
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}
