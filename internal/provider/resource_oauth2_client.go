package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/mitchellh/mapstructure"
	hydra "github.com/ory/hydra-client-go/v2"
)

func resourceOAuth2Client() *schema.Resource {
	return &schema.Resource{
		Description: `OAuth 2.0 clients are used to perform OAuth 2.0 and OpenID Connect flows.
Usually, OAuth 2.0 clients are generated for applications which want to consume your OAuth 2.0 or OpenID Connect capabilities.
To manage ORY Hydra, you will need an OAuth 2.0 Client as well.
Make sure that this endpoint is well protected and only callable by first-party components.
`,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"access_token_strategy": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "Access token strategy to use. Valid options are \"jwt\" and \"opaque\".",
				ValidateFunc: validation.StringInSlice([]string{"jwt", "opaque"}, false),
			},
			"allowed_cors_origins": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"audience": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"backchannel_logout_session_required": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Boolean value specifying whether the RP requires that a sid (session ID) Claim be included in the Logout Token to identify the RP session with the OP when the backchannel_logout_uri is used. If omitted, the default value is false.",
			},
			"backchannel_logout_uri": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "RP URL that will cause the RP to log itself out when sent a Logout Token by the OP.",
			},
			"client_id": {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
				Description:  "ID is the id for this client.",
			},
			"client_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Name is the human-readable string name of the client to be presented to the end-user during authorization.",
			},
			"client_secret": {
				Type:      schema.TypeString,
				Optional:  true,
				Computed:  true,
				Sensitive: true,
				Description: `Secret is the client's secret. The secret will be included in the create request as cleartext, and then never again.
The secret is stored using BCrypt so it is impossible to recover it. Tell your users that they need to write the secret down as it will not be made available again.`,
			},
			"client_secret_expires_at": {
				Type:     schema.TypeInt,
				Optional: true,
				Description: `SecretExpiresAt is an integer holding the time at which the client secret will expire or 0 if it will not expire.
The time is represented as the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time of expiration.
This feature is currently not supported and it's value will always be set to 0.`,
			},
			"client_uri": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "ClientURI is an URL string of a web page providing information about the client. If present, the server SHOULD display this URL to the end-user in a clickable fashion.",
			},
			"contacts": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"frontchannel_logout_session_required": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Boolean value specifying whether the RP requires that iss (issuer) and sid (session ID) query parameters be included to identify the RP session with the OP when the `frontchannel_logout_uri` is used. If omitted, the default value is false.",
			},
			"frontchannel_logout_uri": {
				Type:     schema.TypeString,
				Optional: true,
				Description: `RP URL that will cause the RP to log itself out when rendered in an iframe by the OP.
An iss (issuer) query parameter and a sid (session ID) query parameter MAY be included by the OP to enable the RP to validate the request and to determine which of the potentially multiple sessions is to be logged out;
if either is included, both MUST be.`,
			},
			"grant_types": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
					ValidateFunc: validation.StringInSlice([]string{
						"authorization_code", "client_credentials", "implicit", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer",
					}, false),
				},
			},
			"jwk": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     resourceJWK(),
				Description: `A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key.
A JWK Set is a JSON data structure that represents a set of JWKs.
A JSON Web Key is identified by its set and key id. ORY Hydra uses this functionality to store cryptographic keys used for TLS and JSON Web Tokens (such as OpenID Connect ID tokens), and allows storing user-defined keys as well.`,
			},
			"jwks_uri": {
				Type:     schema.TypeString,
				Optional: true,
				Description: `URL for the Client's JSON Web Key Set [JWK] document.
If the Client signs requests to the Server, it contains the signing key(s) the Server uses to validate signatures from the Client.
The JWK Set MAY also contain the Client's encryption keys(s), which are used by the Server to encrypt responses to the Client.
When both signing and encryption keys are made available, a use (Key Use) parameter value is REQUIRED for all keys in the referenced JWK Set to indicate each key's intended usage.
Although some algorithms allow the same key to be used for both signatures and encryption, doing so is NOT RECOMMENDED, as it is less secure.
The JWK x5c parameter MAY be used to provide X.509 representations of keys provided. When used, the bare key values MUST still be present and MUST match those in the certificate.`,
			},
			"logo_uri": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "LogoURI is an URL string that references a logo for the client.",
			},
			"metadata_json": {
				Type:          schema.TypeString,
				Optional:      true,
				ValidateFunc:  validation.StringIsJSON,
				ConflictsWith: []string{"metadata"},
			},
			"metadata": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				ConflictsWith: []string{"metadata_json"},
			},
			"owner": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Owner is a string identifying the owner of the OAuth 2.0 Client.",
			},
			"policy_uri": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "PolicyURI is a URL string that points to a human-readable privacy policy document that describes how the deployment organization collects, uses, retains, and discloses personal data.",
			},
			"post_logout_redirect_uris": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"redirect_uris": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"request_object_signing_alg": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "JWS [JWS] alg algorithm [JWA] that MUST be used for signing Request Objects sent to the OP. All Request Objects from this Client MUST be rejected, if not signed with this algorithm.",
			},
			"request_uris": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"response_types": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.StringInSlice([]string{"code", "id_token", "token"}, false),
				},
			},
			"sector_identifier_uri": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "URL using the https scheme to be used in calculating Pseudonymous Identifiers by the OP. The URL references a file with a single JSON array of redirect_uri values.",
			},
			"skip_consent": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "SkipConsent skips the consent screen for this client. This field can only be set from the admin API.",
			},
			"subject_type": {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				ValidateFunc: validation.StringInSlice([]string{"pairwise", "public"}, false),
				Description:  "SubjectType requested for responses to this Client. The subject_types_supported Discovery parameter contains a list of the supported subject_type values for this server. Valid types include `pairwise` and `public`.",
			},
			"scopes": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"token_endpoint_auth_method": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				ValidateFunc: validation.StringInSlice([]string{
					"client_secret_basic", "client_secret_post", "none", "private_key_jwt",
				}, false),
				Description: "Requested Client Authentication method for the Token Endpoint. The options are `client_secret_post`, `client_secret_basic`, `private_key_jwt`, and `none`.",
			},
			"token_endpoint_auth_signing_alg": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Requested Client Authentication signing algorithm for the Token Endpoint.",
			},
			"tos_uri": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "TermsOfServiceURI is a URL string that points to a human-readable terms of service document for the client that describes a contractual relationship between the end-user and the client that the end-user accepts when authorizing the client.",
			},
			"userinfo_signed_response_alg": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				Description: `JWS alg algorithm [JWA] REQUIRED for signing UserInfo Responses.
If this is specified, the response will be JWT [JWT] serialized, and signed using JWS.
The default, if omitted, is for the UserInfo Response to return the Claims as a UTF-8 encoded JSON object using the application/json content-type.`,
			},
			"authorization_code_grant_access_token_lifespan": {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "Specify a time duration in milliseconds, seconds, minutes, hours.",
				ValidateFunc:     validation.StringMatch(regexp.MustCompile(`^([0-9]+(ns|us|ms|s|m|h))*$`), "Specify a time duration in milliseconds, seconds, minutes, hours."),
				DiffSuppressFunc: diffSuppressMatchingDurationStrings,
			},
			"authorization_code_grant_id_token_lifespan": {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "Specify a time duration in milliseconds, seconds, minutes, hours.",
				ValidateFunc:     validation.StringMatch(regexp.MustCompile(`^([0-9]+(ns|us|ms|s|m|h))*$`), "Specify a time duration in milliseconds, seconds, minutes, hours."),
				DiffSuppressFunc: diffSuppressMatchingDurationStrings,
			},
			"authorization_code_grant_refresh_token_lifespan": {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "Specify a time duration in milliseconds, seconds, minutes, hours.",
				ValidateFunc:     validation.StringMatch(regexp.MustCompile(`^([0-9]+(ns|us|ms|s|m|h))*$`), "Specify a time duration in milliseconds, seconds, minutes, hours."),
				DiffSuppressFunc: diffSuppressMatchingDurationStrings,
			},
			"client_credentials_grant_access_token_lifespan": {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "Specify a time duration in milliseconds, seconds, minutes, hours.",
				ValidateFunc:     validation.StringMatch(regexp.MustCompile(`^([0-9]+(ns|us|ms|s|m|h))*$`), "Specify a time duration in milliseconds, seconds, minutes, hours."),
				DiffSuppressFunc: diffSuppressMatchingDurationStrings,
			},
			"implicit_grant_access_token_lifespan": {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "Specify a time duration in milliseconds, seconds, minutes, hours.",
				ValidateFunc:     validation.StringMatch(regexp.MustCompile(`^([0-9]+(ns|us|ms|s|m|h))*$`), "Specify a time duration in milliseconds, seconds, minutes, hours."),
				DiffSuppressFunc: diffSuppressMatchingDurationStrings,
			},
			"implicit_grant_id_token_lifespan": {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "Specify a time duration in milliseconds, seconds, minutes, hours.",
				ValidateFunc:     validation.StringMatch(regexp.MustCompile(`^([0-9]+(ns|us|ms|s|m|h))*$`), "Specify a time duration in milliseconds, seconds, minutes, hours."),
				DiffSuppressFunc: diffSuppressMatchingDurationStrings,
			},
			"jwt_bearer_grant_access_token_lifespan": {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "Specify a time duration in milliseconds, seconds, minutes, hours.",
				ValidateFunc:     validation.StringMatch(regexp.MustCompile(`^([0-9]+(ns|us|ms|s|m|h))*$`), "Specify a time duration in milliseconds, seconds, minutes, hours."),
				DiffSuppressFunc: diffSuppressMatchingDurationStrings,
			},
			"refresh_token_grant_access_token_lifespan": {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "Specify a time duration in milliseconds, seconds, minutes, hours.",
				ValidateFunc:     validation.StringMatch(regexp.MustCompile(`^([0-9]+(ns|us|ms|s|m|h))*$`), "Specify a time duration in milliseconds, seconds, minutes, hours."),
				DiffSuppressFunc: diffSuppressMatchingDurationStrings,
			},
			"refresh_token_grant_id_token_lifespan": {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "Specify a time duration in milliseconds, seconds, minutes, hours.",
				ValidateFunc:     validation.StringMatch(regexp.MustCompile(`^([0-9]+(ns|us|ms|s|m|h))*$`), "Specify a time duration in milliseconds, seconds, minutes, hours."),
				DiffSuppressFunc: diffSuppressMatchingDurationStrings,
			},
			"refresh_token_grant_refresh_token_lifespan": {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "Specify a time duration in milliseconds, seconds, minutes, hours.",
				ValidateFunc:     validation.StringMatch(regexp.MustCompile(`^([0-9]+(ns|us|ms|s|m|h))*$`), "Specify a time duration in milliseconds, seconds, minutes, hours."),
				DiffSuppressFunc: diffSuppressMatchingDurationStrings,
			},
		},
		CreateContext: createOAuth2ClientResource,
		ReadContext:   readOAuth2ClientResource,
		UpdateContext: updateOAuth2ClientResource,
		DeleteContext: deleteOAuth2ClientResource,
	}
}

func createOAuth2ClientResource(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	hydraClient := meta.(*ClientConfig).hydraClient

	var oAuth2Client *hydra.OAuth2Client

	client := dataToClient(data)

	err := retryThrottledHydraAction(func() (*http.Response, error) {
		var err error
		var resp *http.Response
		oAuth2Client, resp, err = hydraClient.OAuth2Api.CreateOAuth2Client(ctx).OAuth2Client(*client).Execute()
		return resp, err
	}, meta.(*ClientConfig).backOff)
	if err != nil {
		return diag.FromErr(err)
	}

	return diag.FromErr(dataFromClient(data, oAuth2Client))
}

func readOAuth2ClientResource(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	hydraClient := meta.(*ClientConfig).hydraClient

	var oAuth2Client *hydra.OAuth2Client

	err := retryThrottledHydraAction(func() (*http.Response, error) {
		var resp *http.Response
		var err error

		oAuth2Client, resp, err = hydraClient.OAuth2Api.GetOAuth2Client(ctx, data.Id()).Execute()

		return resp, err
	}, meta.(*ClientConfig).backOff)
	if err != nil {
		var genericOpenAPIError *hydra.GenericOpenAPIError
		if errors.As(err, &genericOpenAPIError) {
			if apiError, ok := genericOpenAPIError.Model().(hydra.ErrorOAuth2); ok && apiError.StatusCode != nil && *apiError.StatusCode == 401 {
				data.SetId("")
				return nil
			}
		}

		return diag.FromErr(err)
	}

	return diag.FromErr(dataFromClient(data, oAuth2Client))
}

func updateOAuth2ClientResource(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	hydraClient := meta.(*ClientConfig).hydraClient

	oAuthClient := dataToClient(data)

	err := retryThrottledHydraAction(func() (*http.Response, error) {
		var err error
		var resp *http.Response
		oAuthClient, resp, err = hydraClient.OAuth2Api.SetOAuth2Client(ctx, data.Id()).OAuth2Client(*oAuthClient).Execute()

		return resp, err
	}, meta.(*ClientConfig).backOff)
	if err != nil {
		return diag.FromErr(err)
	}

	return diag.FromErr(dataFromClient(data, oAuthClient))
}

func deleteOAuth2ClientResource(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	hydraClient := meta.(*ClientConfig).hydraClient

	err := retryThrottledHydraAction(func() (*http.Response, error) {
		return hydraClient.OAuth2Api.DeleteOAuth2Client(ctx, data.Id()).Execute()
	}, meta.(*ClientConfig).backOff)

	return diag.FromErr(err)
}

func dataFromClient(data *schema.ResourceData, oAuthClient *hydra.OAuth2Client) error {
	data.SetId(oAuthClient.GetClientId())
	data.Set("access_token_strategy", oAuthClient.AccessTokenStrategy)
	data.Set("allowed_cors_origins", oAuthClient.AllowedCorsOrigins)
	data.Set("audience", oAuthClient.Audience)
	data.Set("backchannel_logout_session_required", oAuthClient.BackchannelLogoutSessionRequired)
	data.Set("backchannel_logout_uri", oAuthClient.GetBackchannelLogoutUri())
	data.Set("client_id", oAuthClient.GetClientId())
	data.Set("client_name", oAuthClient.ClientName)
	if oAuthClient.ClientSecret != nil {
		data.Set("client_secret", oAuthClient.ClientSecret)
	}
	data.Set("client_secret_expires_at", oAuthClient.ClientSecretExpiresAt)
	data.Set("client_uri", oAuthClient.GetClientUri())
	data.Set("contacts", oAuthClient.Contacts)
	data.Set("frontchannel_logout_session_required", oAuthClient.FrontchannelLogoutSessionRequired)
	data.Set("frontchannel_logout_uri", oAuthClient.GetFrontchannelLogoutUri())
	data.Set("grant_types", oAuthClient.GrantTypes)
	jwks := &hydra.JsonWebKeySet{}
	if err := mapstructure.Decode(oAuthClient.Jwks.(map[string]interface{}), jwks); err != nil {
		return err
	}
	dataFromJWKS(data, jwks, "jwk")
	data.Set("jwks_uri", oAuthClient.GetJwksUri())
	data.Set("logo_uri", oAuthClient.GetLogoUri())
	if metadata, ok := oAuthClient.Metadata.(map[string]interface{}); ok {
		// Check if any nested maps or non-string values exist in metadata
		useMetadataJSON := false
		for _, v := range metadata {
			switch v.(type) {
			case string:
				continue
			default:
				useMetadataJSON = true
			}
		}
		// If metadata contains nested structures or non-string values, use metadata_json
		if useMetadataJSON {
			metadataJSON, err := json.Marshal(metadata)
			if err != nil {
				return err
			}
			data.Set("metadata_json", string(metadataJSON))
			data.Set("metadata", nil)
		} else {
			// If no nested structures or non-string values, use metadata
			data.Set("metadata", metadata)
			data.Set("metadata_json", nil)
		}
	} else {
		data.Set("metadata", nil)
		data.Set("metadata_json", nil)
	}
	data.Set("owner", oAuthClient.Owner)
	data.Set("policy_uri", oAuthClient.GetPolicyUri())
	data.Set("post_logout_redirect_uris", oAuthClient.PostLogoutRedirectUris)
	data.Set("redirect_uris", oAuthClient.RedirectUris)
	data.Set("request_object_signing_alg", oAuthClient.RequestObjectSigningAlg)
	data.Set("request_uris", oAuthClient.RequestUris)
	data.Set("response_types", oAuthClient.ResponseTypes)
	data.Set("sector_identifier_uri", oAuthClient.GetSectorIdentifierUri())
	data.Set("skip_consent", oAuthClient.SkipConsent)
	data.Set("subject_type", oAuthClient.SubjectType)
	if oAuthClient.Scope == nil {
		data.Set("scopes", oAuthClient.Scope)
	} else {
		data.Set("scopes", strings.Split(*oAuthClient.Scope, " "))
	}
	data.Set("token_endpoint_auth_method", oAuthClient.TokenEndpointAuthMethod)
	data.Set("token_endpoint_auth_signing_alg", oAuthClient.TokenEndpointAuthSigningAlg)
	data.Set("tos_uri", oAuthClient.GetTosUri())
	data.Set("userinfo_signed_response_alg", oAuthClient.UserinfoSignedResponseAlg)
	data.Set("authorization_code_grant_access_token_lifespan", oAuthClient.AuthorizationCodeGrantAccessTokenLifespan)
	data.Set("authorization_code_grant_id_token_lifespan", oAuthClient.AuthorizationCodeGrantIdTokenLifespan)
	data.Set("authorization_code_grant_refresh_token_lifespan", oAuthClient.AuthorizationCodeGrantRefreshTokenLifespan)
	data.Set("client_credentials_grant_access_token_lifespan", oAuthClient.ClientCredentialsGrantAccessTokenLifespan)
	data.Set("implicit_grant_access_token_lifespan", oAuthClient.ImplicitGrantAccessTokenLifespan)
	data.Set("implicit_grant_id_token_lifespan", oAuthClient.ImplicitGrantIdTokenLifespan)
	data.Set("jwt_bearer_grant_access_token_lifespan", oAuthClient.JwtBearerGrantAccessTokenLifespan)
	data.Set("refresh_token_grant_access_token_lifespan", oAuthClient.RefreshTokenGrantAccessTokenLifespan)
	data.Set("refresh_token_grant_id_token_lifespan", oAuthClient.RefreshTokenGrantIdTokenLifespan)
	data.Set("refresh_token_grant_refresh_token_lifespan", oAuthClient.RefreshTokenGrantRefreshTokenLifespan)
	return nil
}

func dataToClient(data *schema.ResourceData) *hydra.OAuth2Client {
	client := &hydra.OAuth2Client{}
	if ats, ok := data.GetOk("access_token_strategy"); ok {
		client.AccessTokenStrategy = ptr(ats.(string))
	}
	client.AllowedCorsOrigins = strSlice(data.Get("allowed_cors_origins").([]interface{}))
	client.Audience = strSlice(data.Get("audience").([]interface{}))
	client.SetBackchannelLogoutSessionRequired(data.Get("backchannel_logout_session_required").(bool))
	client.SetBackchannelLogoutUri(data.Get("backchannel_logout_uri").(string))
	client.SetClientId(data.Get("client_id").(string))
	client.SetClientName(data.Get("client_name").(string))
	if cs, ok := data.GetOk("client_secret"); ok {
		client.ClientSecret = ptr(cs.(string))
	}
	if csea, ok := data.GetOk("client_secret_expires_at"); ok {
		client.ClientSecretExpiresAt = ptr(int64(csea.(int)))
	}
	client.SetClientUri(data.Get("client_uri").(string))
	client.Contacts = strSlice(data.Get("contacts").([]interface{}))
	if flsr, ok := data.GetOk("frontchannel_logout_session_required"); ok {
		client.FrontchannelLogoutSessionRequired = ptr(flsr.(bool))
	}
	client.SetFrontchannelLogoutUri(data.Get("frontchannel_logout_uri").(string))
	client.GrantTypes = strSlice(data.Get("grant_types").([]interface{}))
	if jwk, ok := data.GetOk("jwk"); ok && jwk != nil {
		client.Jwks = dataToJWKS(data, "jwk")
	}
	client.SetJwksUri(data.Get("jwks_uri").(string))
	client.SetLogoUri(data.Get("logo_uri").(string))
	if metadataJSON, ok := data.GetOk("metadata_json"); ok {
		var metadata map[string]interface{}
		err := json.Unmarshal([]byte(metadataJSON.(string)), &metadata)
		if err == nil {
			client.Metadata = metadata
		}
	} else if metadata, ok := data.GetOk("metadata"); ok {
		client.Metadata = metadata.(map[string]interface{})
	}
	if o, ok := data.GetOk("owner"); ok {
		client.Owner = ptr(o.(string))
	}
	client.SetPolicyUri(data.Get("policy_uri").(string))
	client.PostLogoutRedirectUris = strSlice(data.Get("post_logout_redirect_uris").([]interface{}))
	client.RedirectUris = strSlice(data.Get("redirect_uris").([]interface{}))
	if rosa, ok := data.GetOk("request_object_signing_alg"); ok {
		client.RequestObjectSigningAlg = ptr(rosa.(string))
	}
	client.RequestUris = strSlice(data.Get("request_uris").([]interface{}))
	client.ResponseTypes = strSlice(data.Get("response_types").([]interface{}))
	client.SetSectorIdentifierUri(data.Get("sector_identifier_uri").(string))
	if sc, ok := data.GetOk("skip_consent"); ok {
		client.SkipConsent = ptr(sc.(bool))
	}
	if st, ok := data.GetOk("subject_type"); ok {
		client.SubjectType = ptr(st.(string))
	}
	scopes := strSlice(data.Get("scopes").([]interface{}))
	if len(scopes) > 0 {
		client.Scope = ptr(strings.Join(scopes, " "))
	}
	if team, ok := data.GetOk("token_endpoint_auth_method"); ok {
		client.TokenEndpointAuthMethod = ptr(team.(string))
	}
	if teasa, ok := data.GetOk("token_endpoint_auth_signing_alg"); ok {
		client.TokenEndpointAuthSigningAlg = ptr(teasa.(string))
	}
	client.SetTosUri(data.Get("tos_uri").(string))
	if usra, ok := data.GetOk("userinfo_signed_response_alg"); ok {
		client.UserinfoSignedResponseAlg = ptr(usra.(string))
	}
	if acaatls, ok := data.GetOk("authorization_code_grant_access_token_lifespan"); ok {
		client.AuthorizationCodeGrantAccessTokenLifespan = ptr(acaatls.(string))
	}
	if acaitls, ok := data.GetOk("authorization_code_grant_id_token_lifespan"); ok {
		client.AuthorizationCodeGrantIdTokenLifespan = ptr(acaitls.(string))
	}
	if acartls, ok := data.GetOk("authorization_code_grant_refresh_token_lifespan"); ok {
		client.AuthorizationCodeGrantRefreshTokenLifespan = ptr(acartls.(string))
	}
	if ccatls, ok := data.GetOk("client_credentials_grant_access_token_lifespan"); ok {
		client.ClientCredentialsGrantAccessTokenLifespan = ptr(ccatls.(string))
	}
	if igatls, ok := data.GetOk("implicit_grant_access_token_lifespan"); ok {
		client.ImplicitGrantAccessTokenLifespan = ptr(igatls.(string))
	}
	if igitls, ok := data.GetOk("implicit_grant_id_token_lifespan"); ok {
		client.ImplicitGrantIdTokenLifespan = ptr(igitls.(string))
	}
	if jbgatls, ok := data.GetOk("jwt_bearer_grant_access_token_lifespan"); ok {
		client.JwtBearerGrantAccessTokenLifespan = ptr(jbgatls.(string))
	}
	if rtgatls, ok := data.GetOk("refresh_token_grant_access_token_lifespan"); ok {
		client.RefreshTokenGrantAccessTokenLifespan = ptr(rtgatls.(string))
	}
	if rtgitls, ok := data.GetOk("refresh_token_grant_id_token_lifespan"); ok {
		client.RefreshTokenGrantIdTokenLifespan = ptr(rtgitls.(string))
	}
	if rtgrtls, ok := data.GetOk("refresh_token_grant_refresh_token_lifespan"); ok {
		client.RefreshTokenGrantRefreshTokenLifespan = ptr(rtgrtls.(string))
	}
	return client
}
