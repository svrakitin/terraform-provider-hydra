package provider

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/ory/hydra-client-go/models"
)

func resourceJWK() *schema.Resource {
	return &schema.Resource{
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
			"kty": {
				Type:     schema.TypeString,
				Required: true,
			},
			"crv": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"d": {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
				Computed:  true,
			},
			"dp": {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
				Computed:  true,
			},
			"dq": {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
				Computed:  true,
			},
			"e": {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
				Computed:  true,
			},
			"k": {
				Type:      schema.TypeString,
				Optional:  true,
				Computed:  true,
				Sensitive: true,
			},
			"n": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"p": {
				Type:      schema.TypeString,
				Optional:  true,
				Computed:  true,
				Sensitive: true,
			},
			"q": {
				Type:      schema.TypeString,
				Optional:  true,
				Computed:  true,
				Sensitive: true,
			},
			"qi": {
				Type:      schema.TypeString,
				Optional:  true,
				Computed:  true,
				Sensitive: true,
			},
			"x": {
				Type:      schema.TypeString,
				Optional:  true,
				Computed:  true,
				Sensitive: true,
			},
			"x5c": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"y": {
				Type:      schema.TypeString,
				Optional:  true,
				Computed:  true,
				Sensitive: true,
			},
		},
	}
}

func dataToJWK(data map[string]interface{}) *models.JSONWebKey {
	return &models.JSONWebKey{
		Alg: strPtr(data["alg"].(string)),
		Kid: strPtr(data["kid"].(string)),
		Use: strPtr(data["use"].(string)),
		Kty: strPtr(data["kty"].(string)),
		Crv: data["crv"].(string),
		D:   data["d"].(string),
		Dp:  data["dp"].(string),
		Dq:  data["dq"].(string),
		E:   data["e"].(string),
		K:   data["k"].(string),
		N:   data["n"].(string),
		P:   data["p"].(string),
		Q:   data["q"].(string),
		Qi:  data["qi"].(string),
		X:   data["x"].(string),
		X5c: strSlice(data["x5c"].([]interface{})),
		Y:   data["y"].(string),
	}
}

func dataFromJWK(jwk *models.JSONWebKey) map[string]interface{} {
	return map[string]interface{}{
		"alg": jwk.Alg,
		"kid": jwk.Kid,
		"use": jwk.Use,
		"kty": jwk.Kty,
		"crv": jwk.Crv,
		"d":   jwk.D,
		"dp":  jwk.Dp,
		"dq":  jwk.Dq,
		"e":   jwk.E,
		"k":   jwk.K,
		"n":   jwk.N,
		"p":   jwk.P,
		"q":   jwk.Q,
		"qi":  jwk.Qi,
		"x":   jwk.X,
		"x5c": jwk.X5c,
		"y":   jwk.Y,
	}
}
