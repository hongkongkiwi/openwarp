// Package client is a small typed client for the OpenWarp REST API. It follows
// openapi.json in the repository root; only the operations the provider needs
// are implemented.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

type APIError struct {
	Status  int
	Message string
	Body    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("openwarp: HTTP %d: %s", e.Status, e.Message)
}

func IsNotFound(err error) bool {
	var api *APIError
	return errors.As(err, &api) && api.Status == http.StatusNotFound
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		request.Header.Set("Authorization", "Bearer "+c.Token)
	}
	response, err := c.HTTP.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		message := strings.TrimSpace(string(raw))
		var parsed struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &parsed) == nil && parsed.Error != "" {
			message = parsed.Error
		}
		return &APIError{Status: response.StatusCode, Message: message, Body: string(raw)}
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func segment(value string) string { return url.PathEscape(value) }

type Org struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"`
}

type App struct {
	ID        string `json:"id"`
	OrgID     string `json:"org_id"`
	Name      string `json:"name"`
	CreatedAt int64  `json:"created_at"`
}

type Env struct {
	ID              string `json:"id"`
	AppID           string `json:"app_id"`
	Name            string `json:"name"`
	Mode            string `json:"mode"`
	Restricted      int64  `json:"restricted"`
	RequireApproval int64  `json:"require_approval"`
}

type Secret struct {
	ID      string  `json:"id"`
	Key     string  `json:"key"`
	Value   *string `json:"value"`
	Path    string  `json:"path"`
	Comment string  `json:"comment"`
	Tags    string  `json:"tags"`
	Type    string  `json:"type"`
	Version int64   `json:"version"`
}

type SecretInput struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Path    string `json:"path,omitempty"`
	Comment string `json:"comment,omitempty"`
	Tags    string `json:"tags,omitempty"`
	Type    string `json:"type,omitempty"`
}

type DeployResult struct {
	Deployed   int64    `json:"deployed"`
	SyncErrors []string `json:"sync_errors"`
}

type ServiceToken struct {
	ID        string `json:"id"`
	AppID     string `json:"app_id"`
	EnvID     string `json:"env_id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	CreatedAt int64  `json:"created_at"`
}

type TokenCreated struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

func (c *Client) Register(ctx context.Context, email, password string) (string, error) {
	var out struct {
		Token string `json:"token"`
	}
	err := c.do(ctx, http.MethodPost, "/api/auth/register", map[string]string{"email": email, "password": password}, &out)
	return out.Token, err
}

// Login exchanges verified credentials for a session token. Registration does
// not return one until the address is verified.
func (c *Client) Login(ctx context.Context, email, password string) (string, error) {
	var out struct {
		Token string `json:"token"`
	}
	err := c.do(ctx, http.MethodPost, "/api/auth/login", map[string]string{"email": email, "password": password}, &out)
	return out.Token, err
}

func (c *Client) ListOrgs(ctx context.Context) ([]Org, error) {
	var out []Org
	return out, c.do(ctx, http.MethodGet, "/api/orgs", nil, &out)
}

func (c *Client) ListApps(ctx context.Context, org string) ([]App, error) {
	var out []App
	return out, c.do(ctx, http.MethodGet, "/api/orgs/"+segment(org)+"/apps", nil, &out)
}

func (c *Client) CreateApp(ctx context.Context, org, name string) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	err := c.do(ctx, http.MethodPost, "/api/orgs/"+segment(org)+"/apps", map[string]string{"name": name}, &out)
	return out.ID, err
}

func (c *Client) RenameApp(ctx context.Context, app, name string) error {
	return c.do(ctx, http.MethodPatch, "/api/apps/"+segment(app), map[string]string{"name": name}, nil)
}

func (c *Client) DeleteApp(ctx context.Context, app string) error {
	return c.do(ctx, http.MethodDelete, "/api/apps/"+segment(app), nil, nil)
}

func (c *Client) ListEnvs(ctx context.Context, app string) ([]Env, error) {
	var out []Env
	return out, c.do(ctx, http.MethodGet, "/api/apps/"+segment(app)+"/envs", nil, &out)
}

func (c *Client) CreateEnv(ctx context.Context, app, name string) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	err := c.do(ctx, http.MethodPost, "/api/apps/"+segment(app)+"/envs", map[string]string{"name": name}, &out)
	return out.ID, err
}

func (c *Client) RenameEnv(ctx context.Context, env, name string) error {
	return c.do(ctx, http.MethodPatch, "/api/envs/"+segment(env), map[string]string{"name": name}, nil)
}

func (c *Client) DeleteEnv(ctx context.Context, env string) error {
	return c.do(ctx, http.MethodDelete, "/api/envs/"+segment(env), nil, nil)
}

func (c *Client) SetEnvPolicy(ctx context.Context, env string, restricted, requireApproval *bool) error {
	body := map[string]any{}
	if restricted != nil {
		body["restricted"] = *restricted
	}
	if requireApproval != nil {
		body["require_approval"] = *requireApproval
	}
	if len(body) == 0 {
		return nil
	}
	return c.do(ctx, http.MethodPut, "/api/envs/"+segment(env)+"/policy", body, nil)
}

func (c *Client) ListSecrets(ctx context.Context, env string) ([]Secret, error) {
	var out struct {
		Secrets []Secret `json:"secrets"`
	}
	err := c.do(ctx, http.MethodGet, "/api/envs/"+segment(env)+"/secrets", nil, &out)
	return out.Secrets, err
}

func (c *Client) DeploySecret(ctx context.Context, env string, secret SecretInput) error {
	body := map[string]any{"secrets": []SecretInput{secret}}
	var out DeployResult
	return c.do(ctx, http.MethodPut, "/api/envs/"+segment(env)+"/secrets", body, &out)
}

func (c *Client) DeleteSecret(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/secrets/"+segment(id), nil, nil)
}

func (c *Client) ListTokens(ctx context.Context, app string) ([]ServiceToken, error) {
	var out []ServiceToken
	return out, c.do(ctx, http.MethodGet, "/api/apps/"+segment(app)+"/tokens", nil, &out)
}

func (c *Client) CreateToken(ctx context.Context, app, name, env string) (*TokenCreated, error) {
	var out TokenCreated
	err := c.do(ctx, http.MethodPost, "/api/apps/"+segment(app)+"/tokens", map[string]string{"name": name, "env_id": env}, &out)
	return &out, err
}

func (c *Client) RevokeToken(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/tokens/"+segment(id), nil, nil)
}
