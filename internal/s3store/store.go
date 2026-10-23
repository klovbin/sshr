// Package s3store keeps a sync account in an S3 bucket, AWS S3, Cloudflare
// R2, MinIO or any other store with PutObject and If-None-Match: *, the
// write that creates the next manifest only when nobody did
package s3store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"sshr.dev/internal/syncclient"
)

// Config says where the account lives, the secret is kept apart from it
// in the keychain
type Config struct {
	Endpoint string `json:"endpoint"`
	Region   string `json:"region"`
	Bucket   string `json:"bucket"`
	// Prefix is the folder of the account in the bucket, one bucket can
	// hold several
	Prefix string `json:"prefix,omitempty"`
	KeyID  string `json:"key_id"`
}

// Store is a syncclient.ObjectStore in a bucket
type Store struct {
	client *s3.Client
	bucket string
	prefix string
}

// requestTimeout bounds one request, a sync runs many small ones
const requestTimeout = time.Minute

// conflictRetries is how often a create is sent again after 409
// ConditionalRequestConflict, S3 asks for a retry then
const conflictRetries = 3

// New opens the bucket of cfg with the secret key secret
func New(cfg Config, secret string, client *http.Client) (*Store, error) {
	if cfg.Endpoint == "" || cfg.Bucket == "" || cfg.KeyID == "" || secret == "" {
		return nil, errors.New("an S3 store needs an endpoint, a bucket, a key id and a secret")
	}
	if err := CheckEndpoint(cfg.Endpoint); err != nil {
		return nil, err
	}
	region := cfg.Region
	if region == "" {
		region = "auto"
	}
	opts := s3.Options{
		Region:       region,
		BaseEndpoint: aws.String(strings.TrimRight(cfg.Endpoint, "/")),
		// a path names the bucket, every S3 clone takes it
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider(cfg.KeyID, secret, ""),
		// checksums only where S3 needs them, several clones refuse the
		// trailing checksums the SDK sends by default
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	}
	if client != nil {
		opts.HTTPClient = client
	}
	prefix := strings.Trim(cfg.Prefix, "/")
	if prefix != "" {
		prefix += "/"
	}
	return &Store{client: s3.New(opts), bucket: cfg.Bucket, prefix: prefix}, nil
}

// CheckEndpoint takes an HTTPS address, plain HTTP only to this machine,
// the sync state can be edited and must not send the requests in the
// clear, a user and password in the address would end up in the state
func CheckEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// the address is not repeated, it may hold a password
		return errors.New("bad S3 endpoint, it has to look like https://host[:port]")
	}
	if u.User != nil {
		return errors.New("the S3 endpoint must not carry a user or password, the key id and secret go apart")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return fmt.Errorf("the S3 endpoint has to be https://, plain http only to this machine: %s", u.Redacted())
}

func ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), requestTimeout)
}

// status is the HTTP status of an error of S3, 0 for another error
func status(err error) int {
	var hs interface{ HTTPStatusCode() int }
	if errors.As(err, &hs) {
		return hs.HTTPStatusCode()
	}
	return 0
}

func (s *Store) key(name string) *string { return aws.String(s.prefix + name) }

// Get reads an object of at most max bytes
func (s *Store) Get(name string, max int) ([]byte, error) {
	c, cancel := ctx()
	defer cancel()
	out, err := s.client.GetObject(c, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: s.key(name)})
	if status(err) == http.StatusNotFound {
		return nil, syncclient.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("S3 get %s: %w", name, err)
	}
	defer out.Body.Close()
	b, err := io.ReadAll(io.LimitReader(out.Body, int64(max)+1))
	if err != nil {
		return nil, fmt.Errorf("S3 get %s: %w", name, err)
	}
	if len(b) > max {
		return nil, syncclient.ErrTooLarge
	}
	return b, nil
}

// Put writes an object over any that is there
func (s *Store) Put(name string, data []byte) error {
	c, cancel := ctx()
	defer cancel()
	_, err := s.client.PutObject(c, &s3.PutObjectInput{Bucket: aws.String(s.bucket), Key: s.key(name), Body: bytes.NewReader(data)})
	if err != nil {
		return fmt.Errorf("S3 put %s: %w", name, err)
	}
	return nil
}

// Create writes an object only when the name is free, S3 decides it in
// the same step as the write, of two creates at once one wins and the
// other gets 412
func (s *Store) Create(name string, data []byte) error {
	for try := 0; ; try++ {
		c, cancel := ctx()
		_, err := s.client.PutObject(c, &s3.PutObjectInput{
			Bucket: aws.String(s.bucket), Key: s.key(name), Body: bytes.NewReader(data),
			IfNoneMatch: aws.String("*"),
		})
		cancel()
		switch code := status(err); {
		case err == nil:
			return nil
		case code == http.StatusPreconditionFailed:
			return syncclient.ErrExists
		case code == http.StatusConflict && try < conflictRetries:
			continue
		default:
			return fmt.Errorf("S3 create %s: %w", name, err)
		}
	}
}

// Delete removes an object, S3 answers a missing one with success too
func (s *Store) Delete(name string) error {
	c, cancel := ctx()
	defer cancel()
	_, err := s.client.DeleteObject(c, &s3.DeleteObjectInput{Bucket: aws.String(s.bucket), Key: s.key(name)})
	if err != nil && status(err) != http.StatusNotFound {
		return fmt.Errorf("S3 delete %s: %w", name, err)
	}
	return nil
}

// List names the objects under prefix, without the prefix of the account
func (s *Store) List(prefix string) ([]string, error) {
	var out []string
	p := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{Bucket: aws.String(s.bucket), Prefix: s.key(prefix)})
	for p.HasMorePages() {
		c, cancel := ctx()
		page, err := p.NextPage(c)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("S3 list %s: %w", prefix, err)
		}
		for _, o := range page.Contents {
			if o.Key != nil {
				out = append(out, strings.TrimPrefix(*o.Key, s.prefix))
			}
		}
	}
	return out, nil
}
