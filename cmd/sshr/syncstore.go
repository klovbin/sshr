package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"sshr.dev/internal/app"
	"sshr.dev/internal/s3store"
	"sshr.dev/internal/syncclient"
)

// storeFlags are the flags of sshr sync init and join that put the account
// in a bucket instead of on sshr-sync
type storeFlags struct {
	backend string
	s3      s3store.Config
}

// take reads the flag at args[i] and its value, it says whether it was one
// of the store flags
func (f *storeFlags) take(args []string, i *int) bool {
	dst := map[string]*string{
		"--backend": &f.backend, "--endpoint": &f.s3.Endpoint, "--bucket": &f.s3.Bucket,
		"--prefix": &f.s3.Prefix, "--region": &f.s3.Region, "--key-id": &f.s3.KeyID,
	}[args[*i]]
	if dst == nil || *i+1 >= len(args) {
		return false
	}
	*i++
	*dst = args[*i]
	return true
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
		return server, nil
	case "s3":
	default:
		return "", fmt.Errorf("unknown sync backend %q, there is s3", f.backend)
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

// s3Address names the bucket in the status, it is not dialed
func s3Address(cfg s3store.Config) string {
	return "s3 " + strings.TrimRight(cfg.Endpoint, "/") + " " + strings.Trim(cfg.Bucket+"/"+cfg.Prefix, "/")
}

// openStore opens the store a sync state names on later runs
func openStore(ref syncclient.BackendRef, secret string) (syncclient.Backend, error) {
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

// joinFlags are the flags a new device passes to sshr sync join, the
// secret key travels apart from them
func joinFlags(st *syncclient.Status) string {
	if st.Backend == nil || st.Backend.Kind != "s3" {
		return "--server " + st.Server
	}
	var cfg s3store.Config
	json.Unmarshal(st.Backend.Config, &cfg)
	out := "--backend s3 --endpoint " + cfg.Endpoint + " --bucket " + cfg.Bucket
	if cfg.Prefix != "" {
		out += " --prefix " + cfg.Prefix
	}
	if cfg.Region != "" {
		out += " --region " + cfg.Region
	}
	return out + " --key-id " + cfg.KeyID
}
