package provider

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/require"
)

var providerFactories = map[string]func() (*schema.Provider, error){
	"hydra": func() (*schema.Provider, error) {
		p := New()
		return p, p.InternalValidate()
	},
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

	jwks, err := os.ReadFile("./fixtures/jwks.json")
	if err != nil {
		t.Fatal("failed to read jwks.json")
	}

	hydraClientStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if u, p, ok := req.BasicAuth(); !ok || u != username || p != password {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	defer hydraClientStub.Close()
	resource.Test(t, resource.TestCase{
		IsUnitTest:        true,
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(testAccProviderBasicAuthConfig, hydraClientStub.URL, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.hydra_jwks.test", "keys.#", "1"),
				),
			},
			{
				Config:      fmt.Sprintf(testAccProviderBasicAuthConfig, hydraClientStub.URL, "invalid", "invalid"),
				ExpectError: regexp.MustCompile("401 Unauthorized"),
			},
		},
	})
}

func TestProvider_httpHeaderAuth(t *testing.T) {
	name := "My-Header"
	value := "t0ps3cr3t"

	jwks, err := os.ReadFile("./fixtures/jwks.json")
	if err != nil {
		t.Fatal("failed to read jwks.json")
	}

	hydraClientStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if v := req.Header.Get(name); v != value {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	defer hydraClientStub.Close()
	resource.Test(t, resource.TestCase{
		IsUnitTest:        true,
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(testAccProviderHttpHeaderConfig, hydraClientStub.URL, name, value),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.hydra_jwks.test", "keys.#", "1"),
				),
			},
		},
	})
}

func TestProvider_tlsAuth(t *testing.T) {
	certFile := "./fixtures/tls.crt"
	keyFile := "./fixtures/tls.key"

	jwks, err := os.ReadFile("./fixtures/jwks.json")
	if err != nil {
		t.Fatal("failed to read jwks.json")
	}

	hydraClientStub := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if len(req.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusBadRequest)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	hydraClientStub.TLS.ClientAuth = tls.RequireAnyClientCert
	defer hydraClientStub.Close()
	resource.Test(t, resource.TestCase{
		IsUnitTest:        true,
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(testAccProviderTLSAuthConfig, hydraClientStub.URL, certFile, keyFile),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.hydra_jwks.test", "keys.#", "1"),
				),
			},
		},
	})
}

func TestProvider_oauth2Auth(t *testing.T) {
	jwks, err := os.ReadFile("./fixtures/jwks.json")
	if err != nil {
		t.Fatal("failed to read jwks.json")
	}

	oauth2, err := os.ReadFile("./fixtures/oauth2.json")
	if err != nil {
		t.Fatal("failed to read oauth2.json")
	}

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
		_, _ = w.Write(oauth2)
	}))
	defer oauth2Server.Close()
	hydraClientStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer test_token" {
			t.Fatal("received unauthorized request")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	defer hydraClientStub.Close()
	resource.Test(t, resource.TestCase{
		IsUnitTest:        true,
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(testAccProviderOAuth2AuthConfig, hydraClientStub.URL, oauth2Server.URL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.hydra_jwks.test", "keys.#", "1"),
				),
			},
		},
	})
}

func testAccPreCheck(t *testing.T) {}

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
}`

	testAccProviderHttpHeaderConfig = `
provider "hydra" {
	endpoint = "%s"

	authentication {
		http_header {
			name  = "%s"
			value = "%s"
		}
	}
}

data "hydra_jwks" "test" {
	name = "test"
}`

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
}`

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
}`
)
