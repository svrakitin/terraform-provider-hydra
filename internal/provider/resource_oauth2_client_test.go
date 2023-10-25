package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccResourceOAuth2Client(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceOAuth2PublicClientConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("hydra_oauth2_client.public", "client_name", "public"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.public", "metadata.first_party", "true"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.public", "redirect_uris.#", "1"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.public", "redirect_uris.0", "http://localhost:8080/callback"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.public", "response_types.#", "1"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.public", "response_types.0", "code"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.public", "token_endpoint_auth_method", "none"),
				),
			},
			{
				Config: testAccResourceOAuth2SecretClientConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("hydra_oauth2_client.secret", "client_name", "secret"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.secret", "client_secret", "secret"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.secret", "redirect_uris.#", "1"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.secret", "redirect_uris.0", "http://localhost:8080/callback"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.secret", "response_types.#", "1"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.secret", "response_types.0", "code"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.secret", "token_endpoint_auth_method", "client_secret_post"),
				),
			},
		},
	})
}

const (
	testAccResourceOAuth2PublicClientConfig = `
provider "hydra" {
  endpoint = "http://localhost:4445"
}

resource "hydra_oauth2_client" "public" {
	client_name = "public"
	metadata = {
		"first_party" = true
	}
	redirect_uris = ["http://localhost:8080/callback"]
	response_types = ["code"]
	token_endpoint_auth_method = "none"
}`

	testAccResourceOAuth2SecretClientConfig = `
provider "hydra" {
  endpoint = "http://localhost:4445"
}

resource "hydra_oauth2_client" "secret" {
	client_name = "secret"
	client_secret = "secret"
	redirect_uris = ["http://localhost:8080/callback"]
	response_types = ["code"]
	token_endpoint_auth_method = "client_secret_post"
}`
)
