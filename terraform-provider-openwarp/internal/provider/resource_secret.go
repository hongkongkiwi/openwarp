package provider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceSecret() *schema.Resource {
	return &schema.Resource{
		CreateContext: writeSecret,
		ReadContext:   readSecret,
		UpdateContext: writeSecret,
		DeleteContext: deleteSecret,
		Schema: map[string]*schema.Schema{
			"app_id":  {Type: schema.TypeString, Required: true, ForceNew: true, Description: "Application owning env_id; validated before writes."},
			"env_id":  {Type: schema.TypeString, Required: true, ForceNew: true},
			"key":     {Type: schema.TypeString, Required: true, ForceNew: true},
			"value":   {Type: schema.TypeString, Required: true, Sensitive: true},
			"path":    {Type: schema.TypeString, Optional: true, Default: "/", ForceNew: true},
			"type":    {Type: schema.TypeString, Optional: true, Default: "secret", ForceNew: true},
			"comment": {Type: schema.TypeString, Optional: true, Default: ""},
		},
	}
}

func writeSecret(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*apiClient)
	env := d.Get("env_id").(string)
	var envs []struct {
		ID string `json:"id"`
	}
	if err := c.request(ctx, http.MethodGet, []string{"apps", d.Get("app_id").(string), "envs"}, nil, &envs); err != nil {
		return diag.FromErr(err)
	}
	belongs := false
	for _, e := range envs {
		if e.ID == env {
			belongs = true
			break
		}
	}
	if !belongs {
		return diag.Errorf("env_id does not belong to app_id")
	}
	path := d.Get("path").(string)
	s := secret{Key: d.Get("key").(string), Value: d.Get("value").(string), Path: path, Type: d.Get("type").(string), Comment: d.Get("comment").(string)}
	// Tags are not managed by this scaffold; preserve existing tags on upsert.
	existing, err := c.find(ctx, env, s.Key, &path)
	if err != nil {
		return diag.FromErr(err)
	}
	if existing != nil {
		s.Tags = existing.Tags
	}
	body := map[string]interface{}{"secrets": []secret{s}}
	if err := c.request(ctx, http.MethodPut, []string{"envs", env, "secrets"}, body, nil); err != nil {
		return diag.FromErr(err)
	}
	// Retain an identity after a successful write, even if refresh then fails.
	d.SetId(env + "/" + s.Key + "/" + path)
	found, err := c.find(ctx, env, s.Key, &path)
	if err != nil {
		return diag.FromErr(err)
	}
	if found == nil {
		return diag.FromErr(fmt.Errorf("secret missing after successful write"))
	}
	d.SetId(found.ID)
	return refreshSecret(d, found)
}

func refreshSecret(d *schema.ResourceData, s *secret) diag.Diagnostics {
	if err := setSecretState(d, s); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("comment", s.Comment); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func readSecret(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	path := d.Get("path").(string)
	s, err := meta.(*apiClient).find(ctx, d.Get("env_id").(string), d.Get("key").(string), &path)
	if err != nil {
		return diag.FromErr(err)
	}
	if s == nil {
		d.SetId("")
		return nil
	}
	d.SetId(s.ID)
	return refreshSecret(d, s)
}

func deleteSecret(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*apiClient)
	path := d.Get("path").(string)
	s, err := c.find(ctx, d.Get("env_id").(string), d.Get("key").(string), &path)
	if err != nil {
		return diag.FromErr(err)
	}
	if s != nil {
		if err := c.request(ctx, http.MethodDelete, []string{"secrets", s.ID}, nil, nil); err != nil {
			return diag.FromErr(err)
		}
	}
	d.SetId("")
	return nil
}
