package openwarp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func mockClient(t *testing.T, method, path, response string, status int, wantBody any) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method || r.RequestURI != path {
			t.Errorf("request = %s %s; want %s %s", r.Method, r.RequestURI, method, path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("missing bearer token")
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Error("missing JSON accept header")
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if wantBody != nil {
			if r.Header.Get("Content-Type") != "application/json" {
				t.Error("missing JSON content type")
			}
			var got any
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Error(err)
			}
			if !reflect.DeepEqual(got, wantBody) {
				t.Errorf("body = %#v; want %#v", got, wantBody)
			}
		} else if len(raw) != 0 {
			t.Errorf("unexpected request body: %s", raw)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, response)
	}))
	t.Cleanup(server.Close)
	return &Client{BaseURL: server.URL + "/", Token: "test-token", HTTPClient: server.Client()}
}

func TestReadMethods(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name, path, response string
		call                 func(*Client) (any, error)
		want                 any
	}{
		{"me", "/api/me", `{"id":"u"}`, func(c *Client) (any, error) { return c.Me(ctx) }, map[string]any{"id": "u"}},
		{"orgs", "/api/orgs", `[{"id":"o","name":"org"}]`, func(c *Client) (any, error) { return c.Orgs(ctx) }, []Org{{ID: "o", Name: "org"}}},
		{"apps", "/api/orgs/o%2F%20%23%3F%25/apps", `[{"id":"a","org_id":"o"}]`, func(c *Client) (any, error) { return c.Apps(ctx, "o/ #?%") }, []App{{ID: "a", OrgID: "o"}}},
		{"envs", "/api/apps/a%2Fb/envs", `[{"id":"e","app_id":"a"}]`, func(c *Client) (any, error) { return c.Envs(ctx, "a/b") }, []Env{{ID: "e", AppID: "a"}}},
		{"secrets", "/api/envs/e%2Ff/secrets", `{"secrets":[{"id":"s","key":"KEY","value":"v","path":"/","type":"secret","version":2}]}`, func(c *Client) (any, error) { return c.Secrets(ctx, "e/f") }, []Secret{{ID: "s", Key: "KEY", Value: "v", Path: "/", Type: "secret", Version: 2}}},
		{"export", "/api/envs/e%2Ff/export", `{"text":"KEY=v\n","secrets":[]}`, func(c *Client) (any, error) { return c.Export(ctx, "e/f") }, map[string]any{"text": "KEY=v\n", "secrets": []any{}}},
		{"leases", "/api/envs/e%2Ff/dynamic", `[{"id":"l","name":"job","value":"v","expires_at":123}]`, func(c *Client) (any, error) { return c.Leases(ctx, "e/f") }, []Lease{{ID: "l", Name: "job", Value: "v", ExpiresAt: 123}}},
		{"audit", "/api/orgs/o%2Fp/audit", `[{"action":"read"}]`, func(c *Client) (any, error) { return c.Audit(ctx, "o/p") }, []map[string]any{{"action": "read"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := mockClient(t, "GET", tc.path, tc.response, 200, nil)
			got, err := tc.call(c)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %#v; want %#v", got, tc.want)
			}
		})
	}
}

func TestSetSecret(t *testing.T) {
	for _, custom := range []bool{false, true} {
		t.Run(map[bool]string{false: "defaults", true: "options"}[custom], func(t *testing.T) {
			path, typ, comment := "", "", ""
			wantPath, wantType := "/", "secret"
			if custom {
				path, typ, comment = "/folder", "plain", "note"
				wantPath, wantType = path, typ
			}
			body := map[string]any{"secrets": []any{map[string]any{"key": "KEY", "value": "雪\nvalue", "path": wantPath, "type": wantType, "comment": comment, "tags": ""}}}
			c := mockClient(t, "PUT", "/api/envs/e%2Ff/secrets", `{"deployed":1,"sync_errors":[]}`, 200, body)
			got, err := c.SetSecret(context.Background(), "e/f", "KEY", "雪\nvalue", path, typ, comment)
			if err != nil {
				t.Fatal(err)
			}
			if got["deployed"] != float64(1) {
				t.Errorf("got %#v", got)
			}
		})
	}
}

func TestCreateLease(t *testing.T) {
	c := mockClient(t, "POST", "/api/envs/e%2Ff/dynamic", `{"id":"l","value":"v","expires_at":123}`, 200, map[string]any{"name": "job", "ttl_secs": float64(3600)})
	got, err := c.CreateLease(context.Background(), "e/f", "job", 3600)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "l" || got.ExpiresAt != 123 {
		t.Errorf("got %#v", got)
	}
}

func TestGetAndDeleteSecret(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Error("missing bearer token")
		}
		if calls <= 2 {
			if r.Method != "GET" || r.RequestURI != "/api/envs/env/secrets" {
				t.Errorf("unexpected lookup: %s %s", r.Method, r.RequestURI)
			}
			_, _ = io.WriteString(w, `{"secrets":[{"id":"s/#","key":"Api_Key","value":"v"}]}`)
		} else {
			if r.Method != "DELETE" || r.RequestURI != "/api/secrets/s%2F%23" {
				t.Errorf("unexpected delete: %s %s", r.Method, r.RequestURI)
			}
			w.WriteHeader(204)
		}
	}))
	defer server.Close()
	c := &Client{BaseURL: server.URL, Token: "token"}
	secret, err := c.GetSecret(context.Background(), "env", "API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if secret.Value != "v" {
		t.Errorf("got %#v", secret)
	}
	result, err := c.DeleteSecret(context.Background(), "env", "api_key")
	if err != nil {
		t.Fatal(err)
	}
	if result != nil || calls != 3 {
		t.Errorf("result %#v, calls %d", result, calls)
	}
}

func TestMissingSecretDoesNotDelete(t *testing.T) {
	c := mockClient(t, "GET", "/api/envs/env/secrets", `{"secrets":[]}`, 200, nil)
	_, err := c.DeleteSecret(context.Background(), "env", "missing")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 404 {
		t.Fatalf("got %v", err)
	}
}

func TestErrors(t *testing.T) {
	for _, tc := range []struct {
		status        int
		body, message string
	}{
		{401, `{"error":"denied"}`, "denied"}, {400, `{"message":"bad"}`, "bad"},
		{500, "broken", "broken"}, {200, "not json", "Invalid JSON response"},
	} {
		t.Run(tc.message, func(t *testing.T) {
			c := mockClient(t, "GET", "/api/me", tc.body, tc.status, nil)
			_, err := c.Me(context.Background())
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("got %v", err)
			}
			if apiErr.Status != tc.status || apiErr.Message != tc.message || apiErr.Body != tc.body {
				t.Errorf("got %#v", apiErr)
			}
		})
	}
}

func TestCanceledContext(t *testing.T) {
	c := mockClient(t, "GET", "/api/me", `{}`, 200, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Me(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}
