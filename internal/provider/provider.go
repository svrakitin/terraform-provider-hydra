package provider

import (
	"context"
	"net/http"
	"net/url"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
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
			"authentication": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"basic": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"username": {
										Type:        schema.TypeString,
										Required:    true,
										DefaultFunc: schema.EnvDefaultFunc("HYDRA_ADMIN_BASIC_AUTH_USERNAME", nil),
									},
									"password": {
										Type:        schema.TypeString,
										Required:    true,
										Sensitive:   true,
										DefaultFunc: schema.EnvDefaultFunc("HYDRA_ADMIN_BASIC_AUTH_PASSWORD", nil),
									},
								},
							},
						},
					},
				},
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

	cfg := &hydraclient.TransportConfig{
		Schemes:  []string{endpointURL.Scheme},
		Host:     endpointURL.Host,
		BasePath: endpointURL.Path,
	}

	var transport runtime.ClientTransport
	if basicAuth, ok := data.GetOk("authentication.0.basic.0"); ok {
		auth := basicAuth.(map[string]interface{})
		tr := &BasicAuthTransport{
			username:     auth["username"].(string),
			password:     auth["password"].(string),
			RoundTripper: http.DefaultTransport,
		}
		httpClient := &http.Client{Transport: tr}
		transport = httptransport.NewWithClient(cfg.Host, cfg.BasePath, cfg.Schemes, httpClient)
	} else {
		transport = httptransport.New(cfg.Host, cfg.BasePath, cfg.Schemes)
	}

	client := hydraclient.New(transport, nil)
	return client.Admin, nil
}

type BasicAuthTransport struct {
	username, password string
	http.RoundTripper
}

func (ct *BasicAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.SetBasicAuth(ct.username, ct.password)
	return ct.RoundTripper.RoundTrip(req)
}
