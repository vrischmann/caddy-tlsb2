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
		waiters:    newWaiters(),
	}, nil
}

type b2Storage struct {
	bucketName string
	client     *b2.Client
	waiters    *waiters
}

func (s *b2Storage) withBucket(op string, fn func(bucket *b2.BucketInfo) error) error {
	bucket, err := s.client.BucketByName(s.bucketName, false)
	if err != nil {
		return &Error{op: op + "/BucketByName", err: err}
	}

	return fn(bucket)
}

func isNotFound(err error) bool {
	v, ok := b2.UnwrapError(err)
	if !ok {
		return false
	}

	return v.Status == http.StatusNotFound
}

func (s *b2Storage) SiteExists(domain string) (res bool, err error) {
	const op = "SiteExists"

	err = s.withBucket(op, func(b *b2.BucketInfo) error {
		l := b.ListFiles("")
		for l.Next() {
			fi := l.FileInfo()
			if fi.Name == mkpath(domain) {
				res = true
				break
			}
		}
		return l.Err()
	})

	return
}

func (s *b2Storage) LoadSite(domain string) (*caddytls.SiteData, error) {
	const op = "LoadSite"

	rd, _, err := s.client.DownloadFileByName(s.bucketName, mkpath(domain))
	if err != nil {
		return nil, &Error{op: op + "/DownloadFileByName", err: err}
	}
	defer rd.Close()

	var data caddytls.SiteData

	dec := json.NewDecoder(rd)
	if err := dec.Decode(&data); err != nil {
		return nil, &Error{op: op + "/Unmarshal", err: err}
	}

	return &data, nil
}

func (s *b2Storage) StoreSite(domain string, data *caddytls.SiteData) error {
	const op = "StoreSite"

	return s.withBucket(op, func(b *b2.BucketInfo) error {
		buf, err := marshalTLSData(data)
		if err != nil {
			return &Error{op: op + "/Marshal", err: err}
		}

		for i := 0; i < maxRetries; i++ {
			_, err = b.Upload(buf, mkpath(domain), "")
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

func (s *b2Storage) DeleteSite(domain string) error {
	const op = "DeleteSite"

	return s.withBucket(op, func(b *b2.BucketInfo) error {
		name := mkpath(domain)
		var id string

		l := b.ListFiles("")
		for l.Next() {
			fi := l.FileInfo()
			if fi.Name == mkpath(domain) {
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

func (s *b2Storage) LoadUser(email string) (*caddytls.UserData, error) {
	const op = "LoadUser"

	rd, _, err := s.client.DownloadFileByName(s.bucketName, mkpath(email))
	if err != nil {
		return nil, &Error{op: op + "/DownloadFileByName", err: err}
	}
	defer rd.Close()

	var data caddytls.UserData

	dec := json.NewDecoder(rd)
	if err := dec.Decode(&data); err != nil {
		return nil, &Error{op: op + "/Unmarshal", err: err}
	}

	return &data, nil
}

func (s *b2Storage) StoreUser(email string, data *caddytls.UserData) error {
	const op = "StoreUser"

	return s.withBucket(op, func(b *b2.BucketInfo) error {
		buf, err := marshalTLSData(data)
		if err != nil {
			return &Error{op: op + "/Marshal", err: err}
		}

		for i := 0; i < maxRetries; i++ {
			_, err = b.Upload(buf, mkpath(email), "")
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

func (s *b2Storage) MostRecentUserEmail() (res string) {
	const op = "MostRecentUserEmail"

	s.withBucket(op, func(b *b2.BucketInfo) error {
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

func (s *b2Storage) TryLock(name string) (caddytls.Waiter, error) {
	wg := s.waiters.forName(name)
	if wg != nil {
		return wg, nil
	}

	s.waiters.add(name)

	return nil, nil
}

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
