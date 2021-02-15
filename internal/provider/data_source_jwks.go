package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/ory/hydra-client-go/client/admin"
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

	adminClient := meta.(*admin.Client)
	resp, err := adminClient.GetJSONWebKeySet(
		admin.NewGetJSONWebKeySetParamsWithContext(ctx).
			WithSet(data.Id()),
	)
	if err != nil {
		return diag.FromErr(err)
	}

	dataFromJWKS(data, resp.Payload, "keys")

	return nil
}
