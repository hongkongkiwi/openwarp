// Package openwarp provides a standard-library client for the OpenWarp API.
package openwarp

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
)

type Client struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

type Secret struct {
	ID      string `json:"id"`
	Key     string `json:"key"`
	Value   string `json:"value"`
	Path    string `json:"path"`
	Type    string `json:"type"`
	Version int    `json:"version"`
	Comment string `json:"comment"`
	Tags    string `json:"tags"`
}

type Env struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	AppID string `json:"app_id"`
}

type App struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	OrgID string `json:"org_id"`
}

type Org struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Lease struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Value     string `json:"value"`
	ExpiresAt int64  `json:"expires_at"`
}

// APIError retains the raw response body. A locally missing key has status 404.
type APIError struct {
	Status  int
	Message string
	Body    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("OpenWarp (%d): %s", e.Status, e.Message)
}

var defaultHTTPClient = &http.Client{Timeout: 30 * time.Second}

func (c *Client) request(ctx context.Context, method, path string, body, out any) error {
	var data io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		data = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, data)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := c.HTTPClient
	if client == nil {
		client = defaultHTTPClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := string(raw)
		var detail struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &detail) == nil {
			if detail.Error != "" {
				message = detail.Error
			} else if detail.Message != "" {
				message = detail.Message
			}
		}
		if message == "" {
			message = resp.Status
		}
		return &APIError{Status: resp.StatusCode, Message: message, Body: string(raw)}
	}
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return &APIError{Status: resp.StatusCode, Message: "Invalid JSON response", Body: string(raw)}
	}
	return nil
}

func (c *Client) Me(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	err := c.request(ctx, http.MethodGet, "/api/me", nil, &out)
	return out, err
}

func (c *Client) Orgs(ctx context.Context) ([]Org, error) {
	var out []Org
	err := c.request(ctx, http.MethodGet, "/api/orgs", nil, &out)
	return out, err
}

func (c *Client) Apps(ctx context.Context, org string) ([]App, error) {
	var out []App
	err := c.request(ctx, http.MethodGet, "/api/orgs/"+url.PathEscape(org)+"/apps", nil, &out)
	return out, err
}

func (c *Client) Envs(ctx context.Context, app string) ([]Env, error) {
	var out []Env
	err := c.request(ctx, http.MethodGet, "/api/apps/"+url.PathEscape(app)+"/envs", nil, &out)
	return out, err
}

func (c *Client) Secrets(ctx context.Context, env string) ([]Secret, error) {
	var out struct {
		Secrets []Secret `json:"secrets"`
	}
	err := c.request(ctx, http.MethodGet, "/api/envs/"+url.PathEscape(env)+"/secrets", nil, &out)
	return out.Secrets, err
}

func (c *Client) GetSecret(ctx context.Context, env, key string) (Secret, error) {
	secrets, err := c.Secrets(ctx, env)
	if err != nil {
		return Secret{}, err
	}
	for _, secret := range secrets {
		if strings.EqualFold(secret.Key, key) {
			return secret, nil
		}
	}
	return Secret{}, &APIError{Status: 404, Message: "Secret not found: " + key}
}

// SetSecret uses path "/" and type "secret" when their arguments are empty.
func (c *Client) SetSecret(ctx context.Context, env, key, value, path, secretType, comment string) (map[string]any, error) {
	if path == "" {
		path = "/"
	}
	if secretType == "" {
		secretType = "secret"
	}
	body := map[string]any{"secrets": []map[string]string{{"key": key, "value": value, "path": path, "type": secretType, "comment": comment, "tags": ""}}}
	var out map[string]any
	err := c.request(ctx, http.MethodPut, "/api/envs/"+url.PathEscape(env)+"/secrets", body, &out)
	return out, err
}

func (c *Client) DeleteSecret(ctx context.Context, env, key string) (map[string]any, error) {
	secret, err := c.GetSecret(ctx, env, key)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	err = c.request(ctx, http.MethodDelete, "/api/secrets/"+url.PathEscape(secret.ID), nil, &out)
	return out, err
}

func (c *Client) Export(ctx context.Context, env string) (map[string]any, error) {
	var out map[string]any
	err := c.request(ctx, http.MethodGet, "/api/envs/"+url.PathEscape(env)+"/export", nil, &out)
	return out, err
}

func (c *Client) Leases(ctx context.Context, env string) ([]Lease, error) {
	var out []Lease
	err := c.request(ctx, http.MethodGet, "/api/envs/"+url.PathEscape(env)+"/dynamic", nil, &out)
	return out, err
}

func (c *Client) CreateLease(ctx context.Context, env, name string, ttlSecs int64) (Lease, error) {
	var out Lease
	err := c.request(ctx, http.MethodPost, "/api/envs/"+url.PathEscape(env)+"/dynamic", map[string]any{"name": name, "ttl_secs": ttlSecs}, &out)
	return out, err
}

func (c *Client) Audit(ctx context.Context, org string) ([]map[string]any, error) {
	var out []map[string]any
	err := c.request(ctx, http.MethodGet, "/api/orgs/"+url.PathEscape(org)+"/audit", nil, &out)
	return out, err
}
