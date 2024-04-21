package provider

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	hydra "github.com/ory/hydra-client-go/v2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

func init() {
	schema.DescriptionKind = schema.StringMarkdown
}

type HydraConfig struct {
	hydraClient *hydra.APIClient
	backOff     *backoff.ExponentialBackOff
}

func New() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"endpoint": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("HYDRA_ADMIN_URL", nil),
			},
			"retry": {
				Type:        schema.TypeList,
				Optional:    true,
				MaxItems:    1,
				Description: "Optional block to configure retry behavior for API requests.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Optional:    true,
							Default:     false,
							Description: "Enable or disable retry behavior.",
						},
						"max_elapsed_time": {
							Type:         schema.TypeString,
							Optional:     true,
							Default:      "30s",
							Description:  "Maximum time to spend retrying requests.",
							ValidateFunc: validateDuration,
						},
						"max_interval": {
							Type:         schema.TypeString,
							Optional:     true,
							Default:      "3s",
							Description:  "Maximum interval between retries.",
							ValidateFunc: validateDuration,
						},
						"randomization_factor": {
							Type:        schema.TypeFloat,
							Optional:    true,
							Default:     0.5,
							Description: "Randomization factor to add jitter to retry intervals.",
						},
					},
				},
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
						"http_header": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:        schema.TypeString,
										Required:    true,
										Description: "Name of the HTTP header to send for authorization.  Defaults to Authorization.",
										DefaultFunc: schema.EnvDefaultFunc("HYDRA_ADMIN_AUTH_HTTP_HEADER_NAME", "Authorization"),
									},
									"value": {
										Type:        schema.TypeString,
										Required:    true,
										Sensitive:   true,
										Description: "Value presented in the configured HTTP header",
										DefaultFunc: schema.EnvDefaultFunc("HYDRA_ADMIN_AUTH_HTTP_HEADER_VALUE", nil),
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

	cfg := hydra.NewConfiguration()
	cfg.HTTPClient = httpClient
	cfg.Servers = hydra.ServerConfigurations{
		{
			URL: endpointURL.String(),
		},
	}

	var backOff *backoff.ExponentialBackOff
	if retry, ok := data.GetOk("retry.0"); ok && data.Get("retry.0.enabled").(bool) {
		backOff = backoff.NewExponentialBackOff()

		retryConfig := retry.(map[string]interface{})

		maxElapsedTime, _ := time.ParseDuration(retryConfig["max_elapsed_time"].(string))
		maxInterval, _ := time.ParseDuration(retryConfig["max_interval"].(string))
		randomizationFactor := retryConfig["randomization_factor"].(float64)

		backOff.MaxElapsedTime = maxElapsedTime
		backOff.MaxInterval = maxInterval
		backOff.RandomizationFactor = randomizationFactor
	}

	return &HydraConfig{
		hydraClient: hydra.NewAPIClient(cfg),
		backOff:     backOff,
	}, nil
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

	if httpHeaderAuth, ok := data.GetOk("authentication.0.http_header.0"); ok {
		auth := httpHeaderAuth.(map[string]interface{})
		httpClient.Transport = &HttpHeaderAuthTransport{
			name:    auth["name"].(string),
			value:   auth["value"].(string),
			Wrapped: httpTransport,
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

type HttpHeaderAuthTransport struct {
	name, value string
	Wrapped     *http.Transport
}

func (hhat *HttpHeaderAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add(hhat.name, hhat.value)
	return hhat.Wrapped.RoundTrip(req)
}
