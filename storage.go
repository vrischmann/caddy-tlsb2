package tlsb2 // import "rischmann.fr/caddy-tlsb2"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync"
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
//
// NOTE: the Locker implemented by this storage is local only right now.
func NewB2Storage(caURL *url.URL) (caddytls.Storage, error) {
	accountID := os.Getenv(EnvNameAccountID)
	if accountID == "" {
		return nil, errors.New("no account ID set, please set $B2_ACCOUNT_ID with either your master account ID or an application key ID")
	}
	accountKey := os.Getenv(EnvNameAccountKey)
	if accountKey == "" {
		return nil, errors.New("no account key set, please set $B2_ACCOUNT_KEY with either your master account key or an application key")
	}
	bucketID := os.Getenv(EnvNameBucket)
	if bucketID == "" {
		return nil, errors.New("no bucket set, please set $B2_BUCKET")
	}

	debugf("account ID: %q, account key: %q, bucket name: %q", accountID, accountKey, bucketID)

	client, err := b2.NewClient(accountID, accountKey, nil)
	if err != nil {
		return nil, err
	}

	return &b2Storage{
		bucketID: bucketID,
		client:   client,
		waiters:  newWaiters(),
	}, nil
}

var debug = os.Getenv("B2_DEBUG") == "1"

func debugf(format string, args ...interface{}) {
	if debug {
		log.Printf("[tlsb2] "+format, args...)
	}
}

type b2Storage struct {
	bucketID string
	client   *b2.Client
	waiters  *waiters
}

func (s *b2Storage) withBucket(op string, fn func(bucket *b2.Bucket) error) error {
	bucket := s.client.BucketByID(s.bucketID)
	return fn(bucket)
}

func (s *b2Storage) fetchName(op string, name string, p interface{}) error {
	return s.withBucket(op, func(b *b2.Bucket) error {
		fi, err := b.GetFileInfoByName(name)
		if err != nil {
			return &Error{op: op + "/GetFileInfoByName", err: err}
		}

		rd, _, err := s.client.DownloadFileByID(fi.ID)
		if err != nil {
			return &Error{op: op + "/DownloadFileByID", err: err}
		}
		defer rd.Close()

		dec := json.NewDecoder(rd)
		if err := dec.Decode(p); err != nil {
			return &Error{op: op + "/Unmarshal", err: err}
		}

		return nil
	})
}

func isNotFound(err error) bool {
	v, ok := b2.UnwrapError(err)
	if !ok {
		return false
	}

	return v.Status == http.StatusNotFound
}

// SiteExists returns true if the domain exists.
func (s *b2Storage) SiteExists(domain string) (res bool, err error) {
	const op = "SiteExists"

	err = s.withBucket(op, func(b *b2.Bucket) error {
		l := b.ListFiles("")
		for l.Next() {
			fi := l.FileInfo()
			if fi.Name == mkDomainPath(domain) {
				res = true
				break
			}
		}
		return l.Err()
	})

	return
}

// LoadSite returns the site data for the domain provided.
func (s *b2Storage) LoadSite(domain string) (*caddytls.SiteData, error) {
	const op = "LoadSite"

	var tmp caddytls.SiteData

	err := s.fetchName(op, mkDomainPath(domain), &tmp)
	if err != nil {
		return nil, err
	}
	return &tmp, err
}

// StoreSite stored the site data for the domain provided.
func (s *b2Storage) StoreSite(domain string, data *caddytls.SiteData) error {
	const op = "StoreSite"

	return s.withBucket(op, func(b *b2.Bucket) error {
		buf, err := marshalTLSData(data)
		if err != nil {
			return &Error{op: op + "/Marshal", err: err}
		}

		for i := 0; i < maxRetries; i++ {
			_, err = b.Upload(buf, mkDomainPath(domain), "")
			if err == nil {
				break
			}

			time.Sleep(1 * time.Second)
		}
		if err != nil {
			return &Error{op: op + "/Upload", err: err}
		}

		return nil
	})
}

// DeleteSite delete a site's data.
func (s *b2Storage) DeleteSite(domain string) error {
	const op = "DeleteSite"

	return s.withBucket(op, func(b *b2.Bucket) error {
		name := mkDomainPath(domain)
		var id string

		l := b.ListFiles("")
		for l.Next() {
			fi := l.FileInfo()
			if fi.Name == mkDomainPath(domain) {
				id = fi.ID
			}
		}

		if err := l.Err(); err != nil {
			return &Error{op: op + "/ListFiles", err: err}
		}

		if err := s.client.DeleteFile(id, name); err != nil {
			return &Error{op: op + "/DeleteFile", err: err}
		}

		return nil
	})
}

// LoadUser returns the user data for the email provided.
func (s *b2Storage) LoadUser(email string) (*caddytls.UserData, error) {
	const op = "LoadUser"

	var tmp caddytls.UserData

	err := s.fetchName(op, mkUserPath(email), &tmp)
	if err != nil {
		return nil, err
	}
	return &tmp, err
}

// StoreUser stores the user data for the email provided.
func (s *b2Storage) StoreUser(email string, data *caddytls.UserData) error {
	const op = "StoreUser"

	return s.withBucket(op, func(b *b2.Bucket) error {
		buf, err := marshalTLSData(data)
		if err != nil {
			return &Error{op: op + "/Marshal", err: err}
		}

		for i := 0; i < maxRetries; i++ {
			_, err = b.Upload(buf, mkUserPath(email), "")
			if err == nil {
				break
			}

			time.Sleep(1 * time.Second)
		}
		if err != nil {
			return &Error{op: op + "/Upload", err: err}
		}

		return nil
	})
}

// MostRecentUserEmail returns the most recently used user email.
func (s *b2Storage) MostRecentUserEmail() (res string) {
	const op = "MostRecentUserEmail"

	s.withBucket(op, func(b *b2.Bucket) error {
		type emailWithTime struct {
			email string
			time  time.Time
		}

		var emails []emailWithTime

		l := b.ListFiles("")
		for l.Next() {
			fi := l.FileInfo()

			emails = append(emails, emailWithTime{
				email: filepath.Base(fi.Name),
				time:  fi.UploadTimestamp,
			})
		}

		sort.Slice(emails, func(i, j int) bool {
			// Reverse sort: most recent first
			return emails[i].time.After(emails[j].time)
		})

		res = emails[0].email

		return nil
	})

	return
}

// TryLock tries to take a lock.
// WARNING: this is only a local lock right now.
func (s *b2Storage) TryLock(name string) (caddytls.Waiter, error) {
	wg := s.waiters.forName(name)
	if wg != nil {
		return wg, nil
	}

	s.waiters.add(name)

	return nil, nil
}

// Unlock removes a lock.
// WARNING: this is only a local lock right now.
func (s *b2Storage) Unlock(name string) error {
	s.waiters.remove(name)
	return nil
}

const maxRetries = 5

// it's a var so we can override it in tests.
var prefix = "caddytls"

func mkpath(path string) string {
	return filepath.Join(prefix, path)
}

func mkDomainPath(path string) string {
	return mkpath(filepath.Join("domain", path))
}

func mkUserPath(path string) string {
	return mkpath(filepath.Join("user", path))
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

type waiters struct {
	mu  sync.Mutex
	wgs map[string]*sync.WaitGroup
}

func newWaiters() *waiters {
	return &waiters{
		wgs: make(map[string]*sync.WaitGroup),
	}
}

func (w *waiters) forName(name string) *sync.WaitGroup {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.wgs[name]
}

func (w *waiters) add(name string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	wg := new(sync.WaitGroup)
	wg.Add(1)

	w.wgs[name] = wg
}

func (w *waiters) remove(name string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	wg, ok := w.wgs[name]
	if !ok {
		return
	}

	wg.Done()
	delete(w.wgs, name)
}
