package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"base_url": {Type: schema.TypeString, Required: true, DefaultFunc: schema.EnvDefaultFunc("OPENWARP_BASE_URL", nil)},
			"token":    {Type: schema.TypeString, Required: true, Sensitive: true, DefaultFunc: schema.EnvDefaultFunc("OPENWARP_TOKEN", nil)},
		},
		ResourcesMap:   map[string]*schema.Resource{"openwarp_secret": resourceSecret()},
		DataSourcesMap: map[string]*schema.Resource{"openwarp_secret": dataSourceSecret()},
		ConfigureContextFunc: func(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
			base, err := url.Parse(d.Get("base_url").(string))
			if err != nil {
				return nil, diag.Errorf("invalid base_url")
			}
			if (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
				return nil, diag.Errorf("base_url must be an HTTP(S) URL without credentials, query, or fragment")
			}
			if d.Get("token").(string) == "" {
				return nil, diag.Errorf("token must not be empty")
			}
			return &apiClient{base: strings.TrimRight(base.String(), "/"), token: d.Get("token").(string), http: &http.Client{
				Timeout:       30 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
			}}, nil
		},
	}
}

type apiClient struct {
	base, token string
	http        *http.Client
}
type secret struct {
	ID      string `json:"id"`
	Key     string `json:"key"`
	Value   string `json:"value"`
	Path    string `json:"path"`
	Type    string `json:"type"`
	Comment string `json:"comment"`
	Tags    string `json:"tags"`
}

func (c *apiClient) request(ctx context.Context, method string, segments []string, body interface{}, out interface{}) error {
	escaped := make([]string, len(segments))
	for i, s := range segments {
		if s == "." || s == ".." {
			return fmt.Errorf("dot path segments are not supported")
		}
		escaped[i] = url.PathEscape(s)
	}
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+"/api/"+strings.Join(escaped, "/"), payload)
	if err != nil {
		return fmt.Errorf("construct OpenWarp request: invalid URL or context")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("OpenWarp request failed (transport error)")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		// API bodies can echo secrets. Do not put them into Terraform diagnostics.
		return fmt.Errorf("OpenWarp API returned HTTP %d", res.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(res.Body).Decode(out); err != nil {
		return fmt.Errorf("decode OpenWarp response: invalid JSON")
	}
	return nil
}

func (c *apiClient) find(ctx context.Context, env, key string, path *string) (*secret, error) {
	var result struct {
		Secrets []secret `json:"secrets"`
	}
	if err := c.request(ctx, http.MethodGet, []string{"envs", env, "secrets"}, nil, &result); err != nil {
		return nil, err
	}
	var found *secret
	for i := range result.Secrets {
		s := &result.Secrets[i]
		if strings.EqualFold(s.Key, key) && (path == nil || s.Path == *path) {
			if found != nil {
				return nil, fmt.Errorf("secret lookup is ambiguous; key exists at multiple paths")
			}
			found = s
		}
	}
	return found, nil
}

func setSecretState(d *schema.ResourceData, s *secret) error {
	for name, value := range map[string]interface{}{"value": s.Value, "path": s.Path, "type": s.Type} {
		if err := d.Set(name, value); err != nil {
			return err
		}
	}
	return nil
}
