# Terraform Hydra Provider

This provider is used to manage [ory/hydra](https://github.com/ory/hydra) resources through Hydra Admin API.

Supported resources:

- OAuth2 Clients (`hydra_oauth2_client` resource)
- JWKS (`hydra_jwks` resource and data source)

See [ory/hydra](https://github.com/ory/hydra) [REST API docs](https://www.ory.sh/hydra/docs/reference/api/) for description of resources.

## Example usage

```hcl
terraform {
  required_providers {
    hydra = {
      source = "svrakitin/hydra"
      version = "0.5.2"
    }
  }
}

provider "hydra" {
  endpoint = "http://hydra-admin.localhost"
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
}

data "hydra_jwks" "default" {
  name = "hydra.openid.id-token"
}

resource "hydra_oauth2_client" "example" {
  client_id   = "example"
  client_name = "example"

  redirect_uris = ["http://localhost:8080/callback"]
  
  response_types             = ["code"]
  token_endpoint_auth_method = "none"
}
```

## Authentication

### Basic Auth

Support for Basic Auth on the Hydra Admin API is available.

```hcl
provider "hydra" {
  endpoint = "http://hydra-admin.localhost"

  authentication {
    basic {
      username = var.hydra_admin_basic_auth_username
      password = var.hydra_admin_basic_auth_password
    }
  }
}
```

### HTTP header

Support for auth using an arbitrary HTTP request header is available.  The header name defaults to `Authorization` if not otherwise set.

```hcl
provider "hydra" {
  endpoint = "http://hydra-admin.localhost"

  authentication {
    http_header {
      name  = var.hydra_admin_auth_http_header_name
      value = var.hydra_admin_auth_http_header_value
    }
  }
}
```
