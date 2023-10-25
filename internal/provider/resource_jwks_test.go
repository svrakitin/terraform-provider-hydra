package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccResourceJWKS_Generated(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceJWKSGeneratedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("hydra_jwks.generated", "key.#", "1"),
					resource.TestCheckResourceAttr("hydra_jwks.generated", "key.0.alg", "RS256"),
					resource.TestCheckResourceAttr("hydra_jwks.generated", "key.0.kid", "generated"),
					resource.TestCheckResourceAttr("hydra_jwks.generated", "key.0.use", "sig"),
					resource.TestCheckResourceAttrSet("hydra_jwks.generated", "key.0.n"),
				),
			},
		},
	})
}

func TestAccResourceJWKS_Inlined(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceJWKSInlinedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("hydra_jwks.inlined", "key.#", "1"),
					resource.TestCheckResourceAttr("hydra_jwks.inlined", "key.0.alg", "RS256"),
					resource.TestCheckResourceAttr("hydra_jwks.inlined", "key.0.kty", "RSA"),
					resource.TestCheckResourceAttr("hydra_jwks.inlined", "key.0.kid", "inlined"),
					resource.TestCheckResourceAttr("hydra_jwks.inlined", "key.0.e", "AQAB"),
					resource.TestCheckResourceAttr("hydra_jwks.inlined", "key.0.use", "sig"),
					resource.TestCheckResourceAttrSet("hydra_jwks.inlined", "key.0.n"),
				),
			},
		},
	})
}

const (
	testAccResourceJWKSGeneratedConfig = `
provider "hydra" {
  endpoint = "http://localhost:4445"
}

resource "hydra_jwks" "generated" {
	name = "generated"

	generator {
		alg = "RS256"
		kid = "generated"
		use = "sig"
		keepers = {
			version = 1
		}
	}
}`

	testAccResourceJWKSInlinedConfig = `
provider "hydra" {
  endpoint = "http://localhost:4445"
}

resource "hydra_jwks" "inlined" {
	name = "inlined"

	key {
		alg = "RS256"
		e = "AQAB"
		kid = "inlined"
		kty = "RSA"
    n = "2yyIpDSNMmWEy22TXVSH1p938ZxWgrfxoQl-Egbc3Gk2nA8MpK_YZCg5oLfyW0kv0mpjq6SsvK0qDKJwjdkeOzLp3qy8Vd-tkP2EF7intFXnkSm_LVPL88d81ysgPXopNL9pgJWTAzTwUZEZtAl5lzG6CLFxThho6XyZOxU-zP-sUK84E8qNfttQ4sdVT0bnl2_j7QOwnid1-c40ZViIb-y_8KHBDpW0RCtDCeaHv-vtgmaFdif-VkliLR8TJfJoWUpxGtmHQVrFXdzyYBCV_zbOxPi4xl-3IGOFZaE4RpvzD_uXI7z2VK2xTldHhcpIeREECAILK9uXo0y-rPbXNRNEQqTcV5WpD9j97n0Sk8NH-itk1no_xy85ubCe_VooOtWMQA7oT1bjco8gBJ7Ww1oNOh9oxtoOpYS9wiShBFTKtFBwhYNlMgERkpTVfR-HWuBSmOXxygfmPsskPUw4xZncmFkFpJi0F4rMtiGO3INWaPEEHZ-bcAqjCNJ4zgl_kECEr7cXAeGHlj69y_n4nRzyVO_l5TJcVCdRiCVxVzbTmX8Cu-MBlX8spTmkHeBdYKHdSNpFfvrwrS_XPjMsldQnnb8ZNmNRP1hZ5EawT3hK6e1hW90DPjGbl07jWrDpozyIFOj-ZKRmqt38CEdyhz3nRg2IJYxuNW6Ljma_wA8"
    use = "sig"
	}
}`
)
