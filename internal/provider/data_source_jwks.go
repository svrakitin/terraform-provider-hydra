package provider

import (
	"context"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	hydra "github.com/ory/hydra-client-go/v2"
)

func dataSourceJWKS() *schema.Resource {
	return &schema.Resource{
		Description: `A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key.
A JWK Set is a JSON data structure that represents a set of JWKs.
A JSON Web Key is identified by its set and key id. ORY Hydra uses this functionality to store cryptographic keys used for TLS and JSON Web Tokens (such as OpenID Connect ID tokens), and allows storing user-defined keys as well.`,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"keys": {
				Type:     schema.TypeList,
				Elem:     resourceJWK(),
				Computed: true,
			},
		},
		ReadContext: readJWKSDataSource,
	}
}

func readJWKSDataSource(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	data.SetId(data.Get("name").(string))

	hydraClient := meta.(*HydraConfig).hydraClient

	var jsonWebKeySet *hydra.JsonWebKeySet

	err := retryThrottledHydraAction(func() (*http.Response, error) {
		var err error
		var resp *http.Response
		jsonWebKeySet, resp, err = hydraClient.JwkApi.GetJsonWebKeySet(ctx, data.Id()).Execute()
		return resp, err
	}, meta.(*HydraConfig).backOff)

	if err != nil {
		return diag.FromErr(err)
	}

	dataFromJWKS(data, jsonWebKeySet, "keys")

	return nil
}
