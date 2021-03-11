package provider

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/url"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/hashicorp/go-cleanhttp"
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
				Type:        schema.TypeList,
				Optional:    true,
				MaxItems:    1,
				Description: "Optional block to specify an authentication method which is used to access Hydra Admin API.",
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
						"tls": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"insecure_skip_verify": {
										Type:        schema.TypeBool,
										Optional:    true,
										DefaultFunc: schema.EnvDefaultFunc("HYDRA_ADMIN_TLS_AUTH_INSECURE", false),
										Description: "Controls whether a client verifies the server's certificate chain and host name.",
									},
									"certificate": {
										Type:        schema.TypeString,
										Required:    true,
										Sensitive:   true,
										DefaultFunc: schema.EnvDefaultFunc("HYDRA_ADMIN_TLS_AUTH_CERT_DATA", nil),
										Description: "PEM-encoded client certificate for TLS authentication.",
									},
									"key": {
										Type:        schema.TypeString,
										Required:    true,
										Sensitive:   true,
										DefaultFunc: schema.EnvDefaultFunc("HYDRA_ADMIN_TLS_AUTH_KEY_DATA", nil),
										Description: "PEM-encoded client certificate key for TLS authentication.",
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

	httpClient, err := configureHTTPClient(data)
	if err != nil {
		return nil, diag.FromErr(err)
	}

	client := hydraclient.New(
		httptransport.NewWithClient(
			endpointURL.Host,
			endpointURL.Path,
			[]string{endpointURL.Scheme},
			httpClient,
		),
		nil,
	)

	return client.Admin, nil
}

func configureHTTPClient(data *schema.ResourceData) (*http.Client, error) {
	httpTransport := cleanhttp.DefaultPooledTransport()
	httpClient := &http.Client{
		Transport: httpTransport,
	}

	if tlsAuth, ok := data.GetOk("authentication.0.tls.0"); ok {
		auth := tlsAuth.(map[string]interface{})
		certificate := bytes.NewBufferString(auth["certificate"].(string)).Bytes()
		key := bytes.NewBufferString(auth["key"].(string)).Bytes()
		insecureSkipVerify := auth["insecure_skip_verify"].(bool)

		cert, err := tls.X509KeyPair(certificate, key)
		if err != nil {
			return nil, err
		}

		httpTransport.TLSClientConfig = &tls.Config{
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: insecureSkipVerify,
		}
	}

	if basicAuth, ok := data.GetOk("authentication.0.basic.0"); ok {
		auth := basicAuth.(map[string]interface{})
		httpClient.Transport = &BasicAuthTransport{
			username: auth["username"].(string),
			password: auth["password"].(string),
			Wrapped:  httpTransport,
		}
	}

	return httpClient, nil
}

type BasicAuthTransport struct {
	username, password string
	Wrapped            *http.Transport
}

func (bat *BasicAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.SetBasicAuth(bat.username, bat.password)
	return bat.Wrapped.RoundTrip(req)
}
