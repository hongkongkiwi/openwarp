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

func (c *Client) request(ctx context.Context, method, path string, body, out any, stepUp ...string) error {
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
	if len(stepUp) == 1 { req.Header.Set("X-OpenWarp-Step-Up", stepUp[0]) }
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

// API calls a route relative to /api; query values never become path components.
func (c *Client) API(ctx context.Context, method string, segments []string, body any, query url.Values, stepUp ...string) (json.RawMessage, error) {
	if len(stepUp) > 1 { return nil, fmt.Errorf("at most one step-up grant is supported") }
	if len(stepUp) == 1 {
		if len(stepUp[0]) == 0 || len(stepUp[0]) > 512 || strings.ContainsFunc(stepUp[0], func(r rune) bool { return r < 32 || r > 126 }) { return nil, fmt.Errorf("invalid step-up grant") }
	}
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
	default:
		return nil, fmt.Errorf("unsupported API method")
	}
	base, err := url.Parse(c.BaseURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" || base.User != nil || strings.ContainsAny(c.BaseURL, "?#") {
		return nil, fmt.Errorf("invalid API base URL")
	}
	path := "/api"
	for _, segment := range segments {
		decoded := segment
		for {
			if strings.Contains(decoded, "\\") || strings.Contains(decoded, "://") || strings.HasPrefix(decoded, "//") || strings.ContainsFunc(decoded, func(r rune) bool { return r < 32 || r == 127 }) {
				return nil, fmt.Errorf("unsafe API path segment")
			}
			for _, component := range strings.Split(decoded, "/") {
				if component == "." || component == ".." { return nil, fmt.Errorf("unsafe API path segment") }
			}
			if !strings.Contains(decoded, "%") { break }
			next, err := url.PathUnescape(decoded)
			if err != nil { return nil, fmt.Errorf("malformed API path encoding") }
			decoded = next
		}
		path += "/" + url.PathEscape(segment)
	}
	if len(query) != 0 { path += "?" + query.Encode() }
	httpClient := c.HTTPClient
	if httpClient == nil { httpClient = defaultHTTPClient }
	clone := *httpClient
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	copy := *c
	copy.HTTPClient = &clone
	var out json.RawMessage
	err = copy.request(ctx, method, path, body, &out, stepUp...)
	return out, err
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
	return c.resolveSecret(ctx, env, key, nil)
}

// GetSecretAtPath selects a secret using its exact path and case-insensitive key.
func (c *Client) GetSecretAtPath(ctx context.Context, env, key, path string) (Secret, error) {
	return c.resolveSecret(ctx, env, key, &path)
}

func (c *Client) completeSecrets(ctx context.Context, env string) ([]Secret, error) {
	path := "/api/envs/" + url.PathEscape(env) + "/secrets"
	offset, total := 0, -1
	var secrets []Secret
	invalid := func() ([]Secret, error) { return nil, &APIError{Status: 0, Message: "Invalid secret pagination response"} }
	for {
		var page struct {
			Secrets json.RawMessage `json:"secrets"`
			Total json.RawMessage `json:"total"`
			Limit json.RawMessage `json:"limit"`
			Offset json.RawMessage `json:"offset"`
		}
		requestPath := path
		if offset != 0 { requestPath += fmt.Sprintf("?offset=%d", offset) }
		if err := c.request(ctx, http.MethodGet, requestPath, nil, &page); err != nil { return nil, err }
		var items []Secret
		if len(page.Secrets) == 0 || string(page.Secrets) == "null" || json.Unmarshal(page.Secrets, &items) != nil { return invalid() }
		if offset == 0 && page.Limit == nil && page.Offset == nil {
			if len(items) > 100_000 { return invalid() }
			if page.Total != nil {
				var total int
				if string(page.Total) == "null" || json.Unmarshal(page.Total, &total) != nil || total != len(items) { return invalid() }
			}
			return items, nil
		}
		var pageTotal, limit, pageOffset int
		if len(page.Total) == 0 || len(page.Limit) == 0 || len(page.Offset) == 0 || string(page.Total) == "null" || string(page.Limit) == "null" || string(page.Offset) == "null" ||
			json.Unmarshal(page.Total, &pageTotal) != nil || json.Unmarshal(page.Limit, &limit) != nil || json.Unmarshal(page.Offset, &pageOffset) != nil { return invalid() }
		if pageTotal < 0 || pageTotal > 100_000 || limit < 1 || limit > 1000 || pageOffset != offset ||
			(total >= 0 && total != pageTotal) || len(items) > limit || offset > pageTotal || len(items) > pageTotal-offset ||
			(offset < pageTotal && len(items) == 0) { return invalid() }
		total = pageTotal
		offset += len(items)
		secrets = append(secrets, items...)
		if offset == total { return secrets, nil }
	}
}

func (c *Client) resolveSecret(ctx context.Context, env, key string, path *string) (Secret, error) {
	secrets, err := c.completeSecrets(ctx, env)
	if err != nil {
		return Secret{}, err
	}
	var match Secret
	found := false
	for _, secret := range secrets {
		if strings.EqualFold(secret.Key, key) && (path == nil || secret.Path == *path) {
			if found {
				return Secret{}, &APIError{Status: 409, Message: "Ambiguous secret: " + key + " matches multiple records"}
			}
			match, found = secret, true
		}
	}
	if !found {
		return Secret{}, &APIError{Status: 404, Message: "Secret not found: " + key}
	}
	return match, nil
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
	return c.deleteSecret(ctx, env, key, nil)
}

// DeleteSecretAtPath deletes the unique secret at the exact path and key.
func (c *Client) DeleteSecretAtPath(ctx context.Context, env, key, path string) (map[string]any, error) {
	return c.deleteSecret(ctx, env, key, &path)
}

func (c *Client) deleteSecret(ctx context.Context, env, key string, path *string) (map[string]any, error) {
	secret, err := c.resolveSecret(ctx, env, key, path)
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
