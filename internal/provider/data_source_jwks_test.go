package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccDataSourceJWKS(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceJWKSConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.hydra_jwks.generated", "keys.#", "1"),
					resource.TestCheckResourceAttr("data.hydra_jwks.generated", "keys.0.alg", "RS256"),
					resource.TestCheckResourceAttr("data.hydra_jwks.generated", "keys.0.kid", "test"),
					resource.TestCheckResourceAttr("data.hydra_jwks.generated", "keys.0.use", "sig"),
				),
			},
		},
	})
}

const (
	testAccDataSourceJWKSConfig = `
provider "hydra" {
  endpoint = "http://localhost:4445"
}

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
}`
)
