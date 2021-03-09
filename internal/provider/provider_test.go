package provider

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
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
		Providers: testAccProviders,
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

func testAccPreCheck(t *testing.T) {
}

const (
	testAccProviderBasicAuthConfig string = `
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
)
