package provider

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/require"
)

var testAccProviders map[string]*schema.Provider
var testAccProvider *schema.Provider

func init() {
	testAccProvider = New()
	testAccProviders = map[string]*schema.Provider{
		"hydra": testAccProvider,
	}
}

func TestProvider(t *testing.T) {
	if err := New().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestProvider_impl(t *testing.T) {
	var _ *schema.Provider = New()
}

func TestProvider_basicAuth(t *testing.T) {
	username := "johndoe"
	password := "p455w0rd"

	hydraAdminStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if u, p, ok := req.BasicAuth(); !ok || u != username || p != password {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer hydraAdminStub.Close()
	resource.Test(t, resource.TestCase{
		IsUnitTest: true,
		Providers:  testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(testAccProviderBasicAuthConfig, hydraAdminStub.URL, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.hydra_jwks.test", "keys.#", "0"),
				),
			},
			{
				Config:      fmt.Sprintf(testAccProviderBasicAuthConfig, hydraAdminStub.URL, "invalid", "invalid"),
				ExpectError: regexp.MustCompile("getJsonWebKeySetUnauthorized"),
			},
		},
	})
}

func TestProvider_httpHeaderAuth(t *testing.T) {
	header := "My-Header"
	credentials := "t0ps3cr3t"

	hydraAdminStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if c := req.Header.Get(header); c != credentials {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer hydraAdminStub.Close()
	resource.Test(t, resource.TestCase{
		IsUnitTest: true,
		Providers:  testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(testAccProviderHttpHeaderConfig, hydraAdminStub.URL, header, credentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.hydra_jwks.test", "keys.#", "0"),
				),
			},
		},
	})
}

func TestProvider_tlsAuth(t *testing.T) {
	certFile := "./fixtures/tls.crt"
	keyFile := "./fixtures/tls.key"

	hydraAdminStub := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if len(req.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusBadRequest)
		}
		w.WriteHeader(http.StatusOK)
	}))
	hydraAdminStub.TLS.ClientAuth = tls.RequireAnyClientCert
	defer hydraAdminStub.Close()
	resource.Test(t, resource.TestCase{
		IsUnitTest: true,
		Providers:  testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(testAccProviderTLSAuthConfig, hydraAdminStub.URL, certFile, keyFile),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.hydra_jwks.test", "keys.#", "0"),
				),
			},
		},
	})
}

func TestProvider_oauth2Auth(t *testing.T) {
	oauth2Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if err := req.ParseForm(); err != nil {
			t.Fatal("failed to parse token endpoint request")
			return
		}

		if !req.PostForm.Has("client_id") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		require.Equal(t, url.Values{
			"grant_type":    []string{"client_credentials"},
			"client_id":     []string{"clientID"},
			"client_secret": []string{"clientSecret"},
			"audience":      []string{"test_audience"},
			"scope":         []string{"test_scope"},
		}, req.PostForm)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"access_token":"test_token","token_type":"Bearer","expires_in":1}`)
	}))
	defer oauth2Server.Close()
	hydraAdminStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer test_token" {
			t.Fatal("received unauthorized request")
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer hydraAdminStub.Close()
	resource.Test(t, resource.TestCase{
		IsUnitTest: true,
		Providers:  testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(testAccProviderOAuth2AuthConfig, hydraAdminStub.URL, oauth2Server.URL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.hydra_jwks.test", "keys.#", "0"),
				),
			},
		},
	})
}

func testAccPreCheck(t *testing.T) {
}

const (
	testAccProviderBasicAuthConfig = `
provider "hydra" {
	endpoint = "%s"

	authentication {
		basic {
			username = "%s"
			password = "%s"
		}
	}
}

data "hydra_jwks" "test" {
	name = "test"
}
`

	testAccProviderHttpHeaderConfig = `
provider "hydra" {
	endpoint = "%s"

	authentication {
		http_header {
			header = "%s"
			credentials  = "%s"
		}
	}
}

data "hydra_jwks" "test" {
	name = "test"
}
`

	testAccProviderTLSAuthConfig = `
provider "hydra" {
	endpoint = "%s"

	authentication {
		tls {
			insecure_skip_verify = true
			certificate          = file("%s")
			key                  = file("%s")
		}
	}
}

data "hydra_jwks" "test" {
	name = "test"
}
`

	testAccProviderOAuth2AuthConfig = `
provider "hydra" {
	endpoint = "%s"

	authentication {
		oauth2 {
			token_endpoint = "%s"
			client_id      = "clientID"
			client_secret  = "clientSecret"
			audience       = ["test_audience"]
			scopes         = ["test_scope"]
		}
	}
}

data "hydra_jwks" "test" {
	name = "test"
}	
	`
)
