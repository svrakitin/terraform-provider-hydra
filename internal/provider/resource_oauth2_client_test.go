package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccResourceOAuth2Client(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceOAuth2ClientConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("hydra_oauth2_client.test", "client_id", "test"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.test", "client_name", "test"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.test", "metadata.first_party", "true"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.test", "redirect_uris.#", "1"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.test", "redirect_uris.0", "http://localhost:8080/callback"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.test", "response_types.#", "1"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.test", "response_types.0", "code"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.test", "token_endpoint_auth_method", "none"),
				),
			},
		},
	})
}

const (
	testAccResourceOAuth2ClientConfig string = `
resource "hydra_oauth2_client" "test" {
	client_id = "test"
	client_name = "test"
	metadata = {
		"first_party" = true
	}
	redirect_uris = ["http://localhost:8080/callback"]
	response_types = ["code"]
	token_endpoint_auth_method = "none"
}
`
)
