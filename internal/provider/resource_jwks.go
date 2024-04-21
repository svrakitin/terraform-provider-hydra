package provider

import (
	"context"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	hydra "github.com/ory/hydra-client-go/v2"
)

func resourceJWKS() *schema.Resource {
	return &schema.Resource{
		Description: `A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key.
A JWK Set is a JSON data structure that represents a set of JWKs.
A JSON Web Key is identified by its set and key id. ORY Hydra uses this functionality to store cryptographic keys used for TLS and JSON Web Tokens (such as OpenID Connect ID tokens), and allows storing user-defined keys as well.`,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"key": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				Elem:     resourceJWK(),
			},
			"generator": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"alg": {
							Type:     schema.TypeString,
							Required: true,
						},
						"kid": {
							Type:     schema.TypeString,
							Required: true,
						},
						"use": {
							Type:     schema.TypeString,
							Required: true,
							ValidateFunc: validation.StringInSlice([]string{
								"sig", "enc",
							}, false),
						},
						"keepers": {
							Type:        schema.TypeMap,
							Required:    true,
							ForceNew:    true,
							Description: "Arbitrary map of values that, when changed, will trigger recreation of resource.",
						},
					},
				},
			},
		},
		CreateContext: createJWKSResource,
		ReadContext:   readJWKSResource,
		UpdateContext: updateJWKSResource,
		DeleteContext: deleteJWKSResource,
	}
}

func createJWKSResource(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if _, ok := data.GetOk("generator"); ok {
		return generateJWKSResource(ctx, data, meta)
	}

	return updateJWKSResource(ctx, data, meta)
}

func generateJWKSResource(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	hydraClient := meta.(*HydraConfig).hydraClient

	setName := data.Get("name").(string)
	generators := data.Get("generator").([]interface{})
	generator := generators[0].(map[string]interface{})

	err := retryThrottledHydraAction(func() (*http.Response, error) {
		_, resp, err := hydraClient.JwkApi.CreateJsonWebKeySet(ctx, setName).CreateJsonWebKeySet(*dataToJWKGeneratorRequest(generator)).Execute()
		return resp, err
	}, meta.(*HydraConfig).backOff)
	if err != nil {
		return diag.FromErr(err)
	}

	data.SetId(setName)

	return readJWKSResource(ctx, data, meta)
}

func readJWKSResource(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
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

	dataFromJWKS(data, jsonWebKeySet, "key")

	return nil
}

func updateJWKSResource(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	hydraClient := meta.(*HydraConfig).hydraClient

	setName := data.Get("name").(string)

	err := retryThrottledHydraAction(func() (*http.Response, error) {
		_, resp, err := hydraClient.JwkApi.SetJsonWebKeySet(ctx, setName).JsonWebKeySet(*dataToJWKS(data, "key")).Execute()
		return resp, err
	}, meta.(*HydraConfig).backOff)
	if err != nil {
		return diag.FromErr(err)
	}

	data.SetId(setName)

	return readJWKSResource(ctx, data, meta)
}

func deleteJWKSResource(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	hydraClient := meta.(*HydraConfig).hydraClient

	setName := data.Get("name").(string)

	err := retryThrottledHydraAction(func() (*http.Response, error) {
		return hydraClient.JwkApi.DeleteJsonWebKeySet(ctx, setName).Execute()
	}, meta.(*HydraConfig).backOff)
	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func dataToJWKGeneratorRequest(data map[string]interface{}) *hydra.CreateJsonWebKeySet {
	return hydra.NewCreateJsonWebKeySet(
		data["alg"].(string),
		data["kid"].(string),
		data["use"].(string),
	)
}

func dataToJWKS(data *schema.ResourceData, key string) *hydra.JsonWebKeySet {
	jwks := &hydra.JsonWebKeySet{}
	for _, jwkData := range data.Get(key).([]interface{}) {
		jwk := dataToJWK(jwkData.(map[string]interface{}))
		jwks.Keys = append(jwks.Keys, *jwk)
	}
	return jwks
}

func dataFromJWKS(data *schema.ResourceData, jwks *hydra.JsonWebKeySet, key string) {
	keys := make([]map[string]interface{}, len(jwks.Keys))
	for i, jwk := range jwks.Keys {
		keys[i] = dataFromJWK(&jwk)
	}
	data.Set(key, keys)
}
