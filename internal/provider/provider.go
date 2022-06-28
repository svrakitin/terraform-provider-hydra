package provider

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	hydraclient "github.com/ory/hydra-client-go/client"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
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
						"oauth2": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"token_endpoint": {
										Type:        schema.TypeString,
										Required:    true,
										DefaultFunc: schema.EnvDefaultFunc("HYDRA_ADMIN_OAUTH2_TOKEN_ENDPOINT", nil),
										Description: "Token endpoint to request an access token",
									},
									"client_id": {
										Type:        schema.TypeString,
										Required:    true,
										DefaultFunc: schema.EnvDefaultFunc("HYDRA_ADMIN_OAUTH2_CLIENT_ID", nil),
										Description: "Client ID",
									},
									"client_secret": {
										Type:        schema.TypeString,
										Required:    true,
										Sensitive:   true,
										DefaultFunc: schema.EnvDefaultFunc("HYDRA_ADMIN_OAUTH2_CLIENT_SECRET", nil),
										Description: "Client Secret",
									},
									"audience": {
										Type:        schema.TypeList,
										Optional:    true,
										DefaultFunc: schema.EnvDefaultFunc("HYDRA_ADMIN_OAUTH2_AUDIENCE", nil),
										Description: "Audience for an issued access token",
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"scopes": {
										Type:        schema.TypeList,
										Optional:    true,
										DefaultFunc: schema.EnvDefaultFunc("HYDRA_ADMIN_OAUTH2_SCOPES", nil),
										Description: "Scopes for an issued access token",
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
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

	if oauth2Auth, ok := data.GetOk("authentication.0.oauth2.0"); ok {
		auth := oauth2Auth.(map[string]interface{})

		clientCredentialsConfig := clientcredentials.Config{
			TokenURL:       auth["token_endpoint"].(string),
			ClientID:       auth["client_id"].(string),
			ClientSecret:   auth["client_secret"].(string),
			Scopes:         strSlice(auth["scopes"].([]interface{})),
			EndpointParams: make(url.Values),
		}
		if rawAudience, ok := auth["audience"]; ok {
			audience := strings.Join(strSlice(rawAudience.([]interface{})), " ")
			clientCredentialsConfig.EndpointParams.Set("audience", audience)
		}

		tokenSource := clientCredentialsConfig.TokenSource(context.Background())
		httpClient.Transport = &oauth2.Transport{
			Base:   httpTransport,
			Source: oauth2.ReuseTokenSource(nil, tokenSource),
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
