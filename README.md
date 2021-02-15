# Terraform Hydra Provider

This provider allow managing [ory/hydra](https://github.com/ory/hydra) following resources through Hydra Admin API:

- OAuth2 Clients (through `hydra_oauth2_client` resource)
- JWKS (through `hydra_jwks` resource and data source)

## Example usage

```hcl
terraform {
  required_providers {
    hydra = {
      source = "svrakitin/hydra"
    }
  }
}

provider "hydra" {
  endpoint = "http://hydra-admin.localhost"
}

resource "hydra_jwks" "generated" {
  name = "generated"

  generator {
    alg     = "RS256"
    kid     = "generated"
    use     = "sig"
    version = "1"
  }
}

data "hydra_jwks" "default" {
  name = "hydra.openid.id-token"
}

resource "hydra_oauth2_client" "example" {
  client_id = "example"
	client_name = "example"

	redirect_uris = ["http://localhost:8080/callback"]
	response_types = ["code"]
	token_endpoint_auth_method = "none"
}
```
