package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/mitchellh/mapstructure"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
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
						"refresh_token", "authorization_code", "client_credentials", "implicit",
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
			"metadata": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
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
					Type: schema.TypeString,
					ValidateFunc: validation.StringInSlice([]string{
						"token", "code", "id_token",
					}, false),
				},
			},
			"sector_identifier_uri": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "URL using the https scheme to be used in calculating Pseudonymous Identifiers by the OP. The URL references a file with a single JSON array of redirect_uri values.",
			},
			"subject_type": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				ValidateFunc: validation.StringInSlice([]string{
					"public", "pairwise",
				}, false),
				Description: "SubjectType requested for responses to this Client. The subject_types_supported Discovery parameter contains a list of the supported subject_type values for this server. Valid types include `pairwise` and `public`.",
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
					"none", "client_secret_basic", "client_secret_post", "private_key_jwt",
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
		},
		CreateContext: createOAuth2ClientResource,
		ReadContext:   readOAuth2ClientResource,
		UpdateContext: updateOAuth2ClientResource,
		DeleteContext: deleteOAuth2ClientResource,
	}
}

func createOAuth2ClientResource(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	adminClient := meta.(*admin.Client)

	client := dataToClient(data)

	resp, err := adminClient.CreateOAuth2Client(
		admin.NewCreateOAuth2ClientParamsWithContext(ctx).
			WithBody(client),
	)
	if err != nil {
		return diag.FromErr(err)
	}

	client = resp.Payload

	return diag.FromErr(dataFromClient(data, client))
}

func readOAuth2ClientResource(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	adminClient := meta.(*admin.Client)

	resp, err := adminClient.GetOAuth2Client(
		admin.NewGetOAuth2ClientParamsWithContext(ctx).
			WithID(data.Id()),
	)
	if err != nil {
		switch err.(type) {
		case *admin.GetOAuth2ClientUnauthorized:
			data.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	client := resp.Payload

	return diag.FromErr(dataFromClient(data, client))
}

func updateOAuth2ClientResource(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	adminClient := meta.(*admin.Client)

	client := dataToClient(data)

	resp, err := adminClient.UpdateOAuth2Client(
		admin.NewUpdateOAuth2ClientParamsWithContext(ctx).
			WithID(data.Id()).
			WithBody(client),
	)
	if err != nil {
		return diag.FromErr(err)
	}

	client = resp.Payload

	return diag.FromErr(dataFromClient(data, client))
}

func deleteOAuth2ClientResource(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	adminClient := meta.(*admin.Client)

	_, err := adminClient.DeleteOAuth2Client(
		admin.NewDeleteOAuth2ClientParamsWithContext(ctx).
			WithID(data.Id()),
	)

	return diag.FromErr(err)
}

func dataFromClient(data *schema.ResourceData, client *models.OAuth2Client) error {
	data.SetId(client.ClientID)
	data.Set("allowed_cors_origins", client.AllowedCorsOrigins)
	data.Set("audience", client.Audience)
	data.Set("backchannel_logout_session_required", client.BackchannelLogoutSessionRequired)
	data.Set("backchannel_logout_uri", client.BackchannelLogoutURI)
	data.Set("client_id", client.ClientID)
	data.Set("client_name", client.ClientName)
	if client.ClientSecret != "" {
		data.Set("client_secret", client.ClientSecret)
	}
	data.Set("client_secret_expires_at", client.ClientSecretExpiresAt)
	data.Set("client_uri", client.ClientURI)
	data.Set("contacts", client.Contacts)
	data.Set("frontchannel_logout_session_required", client.FrontchannelLogoutSessionRequired)
	data.Set("frontchannel_logout_uri", client.FrontchannelLogoutURI)
	data.Set("grant_types", client.GrantTypes)
	jwks := &models.JSONWebKeySet{}
	if err := mapstructure.Decode(client.Jwks.(map[string]interface{}), jwks); err != nil {
		return err
	}
	dataFromJWKS(data, jwks, "jwk")
	data.Set("jwks_uri", client.JwksURI)
	data.Set("logo_uri", client.LogoURI)
	data.Set("metadata", client.Metadata)
	data.Set("owner", client.Owner)
	data.Set("policy_uri", client.PolicyURI)
	data.Set("post_logout_redirect_uris", client.PostLogoutRedirectUris)
	data.Set("redirect_uris", client.RedirectUris)
	data.Set("request_object_signing_alg", client.RequestObjectSigningAlg)
	data.Set("request_uris", client.RequestUris)
	data.Set("response_types", client.ResponseTypes)
	data.Set("sector_identifier_uri", client.SectorIdentifierURI)
	data.Set("subject_type", client.SubjectType)
	data.Set("scopes", strings.Split(client.Scope, " "))
	data.Set("token_endpoint_auth_method", client.TokenEndpointAuthMethod)
	data.Set("token_endpoint_auth_signing_alg", client.TokenEndpointAuthSigningAlg)
	data.Set("tos_uri", client.TosURI)
	data.Set("userinfo_signed_response_alg", client.UserinfoSignedResponseAlg)
	return nil
}

func dataToClient(data *schema.ResourceData) *models.OAuth2Client {
	client := &models.OAuth2Client{}
	client.AllowedCorsOrigins = strSlice(data.Get("allowed_cors_origins").([]interface{}))
	client.Audience = strSlice(data.Get("audience").([]interface{}))
	client.BackchannelLogoutSessionRequired = data.Get("backchannel_logout_session_required").(bool)
	client.BackchannelLogoutURI = data.Get("backchannel_logout_uri").(string)
	client.ClientID = data.Get("client_id").(string)
	client.ClientName = data.Get("client_name").(string)
	if cs, ok := data.GetOk("client_secret"); ok {
		client.ClientSecret = cs.(string)
	}
	client.ClientSecretExpiresAt = int64(data.Get("client_secret_expires_at").(int))
	client.ClientURI = data.Get("client_uri").(string)
	client.Contacts = strSlice(data.Get("contacts").([]interface{}))
	client.FrontchannelLogoutSessionRequired = data.Get("frontchannel_logout_session_required").(bool)
	client.FrontchannelLogoutURI = data.Get("frontchannel_logout_uri").(string)
	client.GrantTypes = strSlice(data.Get("grant_types").([]interface{}))
	// only add jwks if jwk is declared
	if jwk, ok := data.GetOk("jwk"); ok && jwk != nil {
		client.Jwks = dataToJWKS(data, "jwk")
	}
	client.JwksURI = data.Get("jwks_uri").(string)
	client.LogoURI = data.Get("logo_uri").(string)
	client.Metadata = data.Get("metadata")
	client.Owner = data.Get("owner").(string)
	client.PolicyURI = data.Get("policy_uri").(string)
	client.PostLogoutRedirectUris = strSlice(data.Get("post_logout_redirect_uris").([]interface{}))
	client.RedirectUris = strSlice(data.Get("redirect_uris").([]interface{}))
	client.RequestObjectSigningAlg = data.Get("request_object_signing_alg").(string)
	client.RequestUris = strSlice(data.Get("request_uris").([]interface{}))
	client.ResponseTypes = strSlice(data.Get("response_types").([]interface{}))
	client.SectorIdentifierURI = data.Get("sector_identifier_uri").(string)
	client.SubjectType = data.Get("subject_type").(string)
	scopes := strSlice(data.Get("scopes").([]interface{}))
	client.Scope = strings.Join(scopes, " ")
	client.TokenEndpointAuthMethod = data.Get("token_endpoint_auth_method").(string)
	client.TokenEndpointAuthSigningAlg = data.Get("token_endpoint_auth_signing_alg").(string)
	client.TosURI = data.Get("tos_uri").(string)
	client.UserinfoSignedResponseAlg = data.Get("userinfo_signed_response_alg").(string)
	return client
}
