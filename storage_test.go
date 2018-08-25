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

func TestUser(t *testing.T) {
	s := initStorage(t)

	const (
		email1 = "foo@bar.com"
		email2 = "bar@baz.fr"
	)

	userData := &caddytls.UserData{
		Reg: []byte("reg"),
		Key: []byte("key"),
	}

	t.Run("LoadUser", func(t *testing.T) {
		data, err := s.LoadUser(email1)
		if err == nil {
			t.Fatal("expected error")
		}
		if data != nil {
			t.Fatal("expected no data")
		}
	})

	t.Run("StoreUser", func(t *testing.T) {
		err := s.StoreUser(email1, userData)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("LoadUserAfterStore", func(t *testing.T) {
		data, err := s.LoadUser(email1)
		if err != nil {
			t.Fatal(err)
		}

		if v, exp := data.Reg, userData.Reg; !bytes.Equal(v, exp) {
			t.Fatalf("expected reg %q to be equal to %q", string(v), string(exp))
		}
		if v, exp := data.Key, userData.Key; !bytes.Equal(v, exp) {
			t.Fatalf("expected key %q to be equal to %q", string(v), string(exp))
		}
	})

	t.Run("MostRecentUserEmail", func(t *testing.T) {
		err := s.StoreUser(email2, userData)
		if err != nil {
			t.Fatal(err)
		}

		tmp := s.MostRecentUserEmail()
		if tmp != email2 {
			t.Fatalf("expected most recent user email to be %q, got %q", email2, tmp)
		}
	})
}
