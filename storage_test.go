// +build full

package tlsb2

import (
	"bytes"
	"net/url"
	"strings"
	"testing"

	"github.com/mholt/caddy/caddytls"
)

const testCAURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

func init() {
	prefix = "test_caddytls"
}

func initStorage(t *testing.T) caddytls.Storage {
	caURL, _ := url.Parse(testCAURL)

	s, err := NewB2Storage(caURL)
	if err != nil {
		t.Fatal(err)
	}

	truncateStorage(t, s.(*b2Storage))

	return s
}

func truncateStorage(t *testing.T, s *b2Storage) {
	bucket, err := s.client.BucketByName(s.bucketName, false)
	if err != nil {
		t.Fatal(err)
	}

	type fileToDelete struct {
		name string
		id   string
	}

	var toDelete []fileToDelete

	l := bucket.ListFilesVersions("", "")
	for l.Next() {
		fi := l.FileInfo()
		if strings.HasPrefix(fi.Name, prefix) {
			toDelete = append(toDelete, fileToDelete{
				name: fi.Name,
				id:   fi.ID,
			})
		}
	}

	if err := l.Err(); err != nil {
		t.Fatal(err)
	}

	for _, v := range toDelete {
		err := s.client.DeleteFile(v.id, v.name)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestSite(t *testing.T) {
	s := initStorage(t)

	const domain = "foobar.com"

	siteData := &caddytls.SiteData{
		Cert: []byte("cert"),
		Key:  []byte("key"),
		Meta: []byte("meta"),
	}

	t.Run("SiteExists", func(t *testing.T) {
		exists, err := s.SiteExists(domain)
		if err != nil {
			t.Fatal(err)
		}

		if exists {
			t.Errorf("expected site to not exists")
		}
	})

	//

	t.Run("StoreSite", func(t *testing.T) {
		err := s.StoreSite(domain, siteData)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("SiteExistsAfterStore", func(t *testing.T) {
		exists, err := s.SiteExists(domain)
		if err != nil {
			t.Fatal(err)
		}

		if !exists {
			t.Errorf("expected site to exists")
		}
	})

	//

	t.Run("LoadSite", func(t *testing.T) {
		tmp, err := s.LoadSite(domain)
		if err != nil {
			t.Fatal(err)
		}

		if tmp == nil {
			t.Fatal("expected site data to not be nil")
		}

		if v, exp := tmp.Cert, siteData.Cert; !bytes.Equal(v, exp) {
			t.Fatalf("expected cert %q to be equal to %q", string(v), string(exp))
		}
		if v, exp := tmp.Key, siteData.Key; !bytes.Equal(v, exp) {
			t.Fatalf("expected key %q to be equal to %q", string(v), string(exp))
		}
		if v, exp := tmp.Meta, siteData.Meta; !bytes.Equal(v, exp) {
			t.Fatalf("expected meta %q to be equal to %q", string(v), string(exp))
		}
	})

	//

	t.Run("DeleteSite", func(t *testing.T) {
		err := s.DeleteSite(domain)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("SiteExistsAfterDelete", func(t *testing.T) {
		exists, err := s.SiteExists(domain)
		if err != nil {
			t.Fatal(err)
		}

		if exists {
			t.Errorf("expected site to not exists")
		}
	})
}
