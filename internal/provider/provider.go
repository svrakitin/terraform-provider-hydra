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
			"basic_auth_user": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("HYDRA_ADMIN_AUTH_USER", nil),
			},
			"basic_auth_pass": {
				Type:        schema.TypeString,
				Sensitive:   true,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("HYDRA_ADMIN_AUTH_PASS", nil),
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
	authUser := data.Get("basic_auth_user").(string)
	authPass := data.Get("basic_auth_pass").(string)
	if authUser != "" && authPass != "" {
		tr := &BasicAuthTransport{user: authUser, pass: authPass, RoundTripper: http.DefaultTransport}
		httpClient := &http.Client{Transport: tr}
		transport = httptransport.NewWithClient(cfg.Host, cfg.BasePath, cfg.Schemes, httpClient)
	} else {
		transport = httptransport.New(cfg.Host, cfg.BasePath, cfg.Schemes)
	}

	client := hydraclient.New(transport, nil)
	return client.Admin, nil
}

type BasicAuthTransport struct {
	user, pass string
	http.RoundTripper
}

func (ct *BasicAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.SetBasicAuth(ct.user, ct.pass)
	return ct.RoundTripper.RoundTrip(req)
}
