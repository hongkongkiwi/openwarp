package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceSecret() *schema.Resource {
	return &schema.Resource{
		ReadContext: func(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
			s, err := meta.(*apiClient).find(ctx, d.Get("env_id").(string), d.Get("key").(string), nil)
			if err != nil {
				return diag.FromErr(err)
			}
			if s == nil {
				return diag.Errorf("secret not found")
			}
			if err := setSecretState(d, s); err != nil {
				return diag.FromErr(err)
			}
			d.SetId(s.ID)
			return nil
		},
		Schema: map[string]*schema.Schema{
			"env_id": {Type: schema.TypeString, Required: true},
			"key":    {Type: schema.TypeString, Required: true},
			"value":  {Type: schema.TypeString, Computed: true, Sensitive: true},
			"path":   {Type: schema.TypeString, Computed: true},
			"type":   {Type: schema.TypeString, Computed: true},
		},
	}
}
