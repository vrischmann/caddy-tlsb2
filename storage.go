package tlsb2 // import "rischmann.fr/caddytls-b2"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/FiloSottile/b2"
	"github.com/mholt/caddy/caddytls"
)

func init() {
	caddytls.RegisterStorageProvider("b2", NewB2Storage)
}

const (
	// EnvNameAccountID is the name of the environment variable containing the account ID or application key ID.
	EnvNameAccountID = "B2_ACCOUNT_ID"

	// EnvNameAccountKey is the name of the environment variable containing the account master key or application key.
	EnvNameAccountKey = "B2_ACCOUNT_KEY"

	// EnvNameBucket is the bucket containing the files.
	EnvNameBucket = "B2_BUCKET"
)

// NewB2Storage creates a new caddytls.Storage for the given Certificate Authority URL.
//
// Credentials for b2 are read from environment variables.
// See the constants to know their names and uses.
func NewB2Storage(caURL *url.URL) (caddytls.Storage, error) {
	accountID := os.Getenv(EnvNameAccountID)
	if accountID == "" {
		return nil, errors.New("no account ID set, please set $B2_ACCOUNT_ID with either your master account ID or an application key ID")
	}
	accountKey := os.Getenv(EnvNameAccountKey)
	if accountKey == "" {
		return nil, errors.New("no account key set, please set $B2_ACCOUNT_KEY with either your master account key or an application key")
	}
	bucketName := os.Getenv(EnvNameBucket)
	if bucketName == "" {
		return nil, errors.New("no bucket set, please set $B2_BUCKET")
	}

	client, err := b2.NewClient(accountID, accountKey, nil)
	if err != nil {
		return nil, err
	}

	return &b2Storage{
		bucketName: bucketName,
		client:     client,
	}, nil
}

type b2Storage struct {
	bucketName string
	client     *b2.Client
}

func isNotFound(err error) bool {
	v, ok := b2.UnwrapError(err)
	if !ok {
		return false
	}

	return v.Status == http.StatusNotFound
}

func (s *b2Storage) SiteExists(domain string) (bool, error) {
	const op = "SiteExists"

	bucket, err := s.client.BucketByName(s.bucketName, false)
	if err != nil {
		return false, &Error{op: op + "/BucketByName", err: err}
	}

	l := bucket.ListFiles("")
	for l.Next() {
		fi := l.FileInfo()
		if fi.Name == mkpath(domain) {
			return true, l.Err()
		}
	}

	return false, l.Err()
}

func (s *b2Storage) LoadSite(domain string) (*caddytls.SiteData, error) {
	panic("not implemented")
}

func (s *b2Storage) StoreSite(domain string, data *caddytls.SiteData) error {
	const op = "StoreSite"

	bucket, err := s.client.BucketByName(s.bucketName, false)
	if err != nil {
		return &Error{op: op + "/BucketByName", err: err}
	}

	buf, err := marshalTLSData(data)
	if err != nil {
		return &Error{op: op + "/marshal", err: err}
	}

	for i := 0; i < maxRetries; i++ {
		_, err = bucket.Upload(buf, mkpath(domain), "")
		if err == nil {
			break
		}

		time.Sleep(1 * time.Second)
	}
	if err != nil {
		return &Error{op: op + "/Upload", err: err}
	}

	return nil
}

func (s *b2Storage) DeleteSite(domain string) error {
	panic("not implemented")
}

func (s *b2Storage) LoadUser(email string) (*caddytls.UserData, error) {
	panic("not implemented")
}

func (s *b2Storage) StoreUser(email string, data *caddytls.UserData) error {
	panic("not implemented")
}

func (s *b2Storage) MostRecentUserEmail() string {
	panic("not implemented")
}

func (s *b2Storage) TryLock(name string) (caddytls.Waiter, error) {
	panic("not implemented")
}

func (s *b2Storage) Unlock(name string) error {
	panic("not implemented")
}

const maxRetries = 5

// it's a var so we can override it in tests.
var prefix = "caddytls"

func mkpath(path string) string {
	return filepath.Join(prefix, path)
}

// Error represents an error from tlsb2
type Error struct {
	op  string
	err error
}

func (e *Error) Error() string {
	v, ok := b2.UnwrapError(e.err)
	if ok {
		return fmt.Sprintf("op:%s b2:%v", e.op, v)
	}

	return fmt.Sprintf("op:%s err:%v", e.op, e.err)
}

func marshalTLSData(d interface{}) (*bytes.Buffer, error) {
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)

	err := enc.Encode(d)

	return buf, err
}
