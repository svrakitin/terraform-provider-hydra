package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccDataSourceJWKS(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceJWKSConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.hydra_jwks.generated", "keys.#", "2"),
					resource.TestCheckResourceAttr("data.hydra_jwks.generated", "keys.0.alg", "RS256"),
					resource.TestCheckResourceAttr("data.hydra_jwks.generated", "keys.0.kid", "public:test"),
					resource.TestCheckResourceAttr("data.hydra_jwks.generated", "keys.0.use", "sig"),
					resource.TestCheckResourceAttr("data.hydra_jwks.generated", "keys.1.alg", "RS256"),
					resource.TestCheckResourceAttr("data.hydra_jwks.generated", "keys.1.kid", "private:test"),
					resource.TestCheckResourceAttr("data.hydra_jwks.generated", "keys.1.use", "sig"),
				),
			},
		},
	})
}

const (
	testAccDataSourceJWKSConfig string = `
resource "hydra_jwks" "generated" {
	name = "generated"

	generator {
		alg = "RS256"
		kid = "test"
		use = "sig"
		keepers = {
			version = 1
		}
	}
}

data "hydra_jwks" "generated" {
	name = hydra_jwks.generated.name
}
`
)
