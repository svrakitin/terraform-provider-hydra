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
			{
				Config: testAccResourceOAuth2ClientWithMetadataJSON,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("hydra_oauth2_client.client_with_metadata_json", "client_name", "client_with_metadata_json"),
					checkResourceAttrJSON("hydra_oauth2_client.client_with_metadata_json", "metadata_json", `{"nested": {"key": "value"}, "first_party": true}`),
					resource.TestCheckResourceAttr("hydra_oauth2_client.client_with_metadata_json", "redirect_uris.#", "1"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.client_with_metadata_json", "redirect_uris.0", "http://localhost:8080/callback"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.client_with_metadata_json", "response_types.#", "1"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.client_with_metadata_json", "response_types.0", "code"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.client_with_metadata_json", "token_endpoint_auth_method", "none"),
				),
			},
			{
				Config: testAccResourceOAuth2DeviceCodeClientConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("hydra_oauth2_client.device_code", "client_name", "device_code"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.device_code", "token_endpoint_auth_method", "none"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.device_code", "grant_types.#", "3"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.device_code", "grant_types.0", "authorization_code"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.device_code", "grant_types.1", "refresh_token"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.device_code", "grant_types.2", "urn:ietf:params:oauth:grant-type:device_code"),
				),
			},
			{
				Config: testAccResourceOAuth2TokenExchangeClientConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("hydra_oauth2_client.token_exchange", "client_name", "token_exchange"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.token_exchange", "token_endpoint_auth_method", "client_secret_post"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.token_exchange", "grant_types.#", "2"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.token_exchange", "grant_types.0", "client_credentials"),
					resource.TestCheckResourceAttr("hydra_oauth2_client.token_exchange", "grant_types.1", "urn:ietf:params:oauth:grant-type:token-exchange"),
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

	testAccResourceOAuth2ClientWithMetadataJSON = `
provider "hydra" {
  endpoint = "http://localhost:4445"
}

resource "hydra_oauth2_client" "client_with_metadata_json" {
	client_name = "client_with_metadata_json"
	metadata_json = jsonencode({
		"nested" = {
			"key" = "value"
		},
		"first_party" = true
	})
	redirect_uris = ["http://localhost:8080/callback"]
	response_types = ["code"]
	token_endpoint_auth_method = "none"
}`

	testAccResourceOAuth2DeviceCodeClientConfig = `
provider "hydra" {
  endpoint = "http://localhost:4445"
}

resource "hydra_oauth2_client" "device_code" {
	client_name = "device_code"
	grant_types = [
		"authorization_code",
		"refresh_token",
		"urn:ietf:params:oauth:grant-type:device_code",
	]
	redirect_uris = ["http://localhost:8080/callback"]
	response_types = ["code"]
	token_endpoint_auth_method = "none"
}`

	testAccResourceOAuth2TokenExchangeClientConfig = `
provider "hydra" {
  endpoint = "http://localhost:4445"
}

resource "hydra_oauth2_client" "token_exchange" {
	client_name = "token_exchange"
	client_secret = "secret"
	grant_types = [
		"client_credentials",
		"urn:ietf:params:oauth:grant-type:token-exchange",
	]
	token_endpoint_auth_method = "client_secret_post"
}`
)
