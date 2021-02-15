package provider

import (
	"context"
	"net/url"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	hydraclient "github.com/ory/hydra-client-go/client"
)

func init() {
	schema.DescriptionKind = schema.StringMarkdown
}

func New() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"endpoint": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("HYDRA_ADMIN_URL", nil),
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"hydra_oauth2_client": resourceOAuth2Client(),
			"hydra_jwks":          resourceJWKS(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"hydra_jwks": dataSourceJWKS(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(ctx context.Context, data *schema.ResourceData) (interface{}, diag.Diagnostics) {
	endpoint := data.Get("endpoint").(string)

	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, diag.FromErr(err)
	}

	client := hydraclient.NewHTTPClientWithConfig(nil, &hydraclient.TransportConfig{
		Schemes:  []string{endpointURL.Scheme},
		Host:     endpointURL.Host,
		BasePath: endpointURL.Path,
	})

	return client.Admin, nil
}
