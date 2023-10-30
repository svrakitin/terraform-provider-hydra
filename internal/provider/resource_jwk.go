package provider

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	hydra "github.com/ory/hydra-client-go/v2"
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

func dataToJWK(data map[string]interface{}) *hydra.JsonWebKey {
	jwk := &hydra.JsonWebKey{
		Alg: data["alg"].(string),
		Kid: data["kid"].(string),
		Use: data["use"].(string),
		Kty: data["kty"].(string),
	}
	if crv := data["crv"].(string); crv != "" {
		jwk.Crv = &crv
	}
	if d := data["d"].(string); d != "" {
		jwk.D = &d
	}
	if dp := data["dp"].(string); dp != "" {
		jwk.Dp = &dp
	}
	if dq := data["dq"].(string); dq != "" {
		jwk.Dq = &dq
	}
	if e := data["e"].(string); e != "" {
		jwk.E = &e
	}
	if k := data["k"].(string); k != "" {
		jwk.K = &k
	}
	if n := data["n"].(string); n != "" {
		jwk.N = &n
	}
	if p := data["p"].(string); p != "" {
		jwk.P = &p
	}
	if q := data["q"].(string); q != "" {
		jwk.Q = &q
	}
	if qi := data["qi"].(string); qi != "" {
		jwk.Qi = &qi
	}
	if x := data["x"].(string); x != "" {
		jwk.X = &x
	}
	if x5c := data["x5c"].([]interface{}); len(x5c) > 0 {
		jwk.X5c = strSlice(x5c)
	}
	if y := data["y"].(string); y != "" {
		jwk.Y = &y
	}
	return jwk
}

func dataFromJWK(jwk *hydra.JsonWebKey) map[string]interface{} {
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
