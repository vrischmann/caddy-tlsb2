// +build full

package tlsb2

import (
	"bytes"
	"net/url"
	"testing"

	"github.com/mholt/caddy/caddytls"
)

const testCAURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

func initStorage(t *testing.T) caddytls.Storage {
	caURL, _ := url.Parse(testCAURL)

	s, err := NewB2Storage(caURL)
	if err != nil {
		t.Fatal(err)
	}

	return s
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
}
