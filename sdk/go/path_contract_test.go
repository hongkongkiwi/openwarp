package openwarp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
)

var pathContractSecrets = []Secret{
	{ID: "other", Key: "OTHER", Path: "/team/", Value: "dummy-other"},
	{ID: "folder", Key: "API_KEY", Path: "/team/", Value: "dummy-folder"},
	{ID: "nested", Key: "API_KEY", Path: "/team/nested/", Value: "dummy-nested"},
	{ID: "root", Key: "API_KEY", Path: "/", Value: "dummy-root"},
}

type pathContractRequest struct {
	method, path string
	authorized   bool
}

func pathContractClient(t *testing.T, secrets []Secret) (*Client, func(...string)) {
	t.Helper()
	var mu sync.Mutex
	var calls []pathContractRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorized := r.Header.Get("Authorization") == "Bearer path-contract-dummy-token"
		mu.Lock()
		calls = append(calls, pathContractRequest{r.Method, r.RequestURI, authorized})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if !authorized {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		if r.Method == http.MethodGet && r.RequestURI == "/api/envs/env/secrets" {
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": secrets})
			return
		}
		for _, secret := range secrets {
			if r.Method == http.MethodDelete && r.RequestURI == "/api/secrets/"+secret.ID {
				_, _ = w.Write([]byte(`{"deleted":true}`))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"unexpected fixture route"}`))
	}))
	t.Cleanup(server.Close)
	assertCalls := func(want ...string) {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		got := make([]string, 0, len(calls))
		for _, call := range calls {
			if !call.authorized {
				t.Error("request omitted fixture bearer token")
			}
			got = append(got, call.method+" "+call.path)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("requests = %v; want %v", got, want)
		}
	}
	return &Client{BaseURL: server.URL, Token: "path-contract-dummy-token", HTTPClient: server.Client()}, assertCalls
}

func pathContractError(t *testing.T, err error, status int) {
	t.Helper()
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError status %d, got %v", status, err)
	}
	if apiErr.Status != status {
		t.Errorf("error status = %d; want %d", apiErr.Status, status)
	}
}

// Runtime assertions keep the legacy ambiguity reproductions runnable before these methods exist.
type pathContractMethods interface {
	GetSecretAtPath(context.Context, string, string, string) (Secret, error)
	DeleteSecretAtPath(context.Context, string, string, string) (map[string]any, error)
}

func pathContractAPI(t *testing.T, c *Client) pathContractMethods {
	t.Helper()
	api, ok := any(c).(pathContractMethods)
	if !ok {
		t.Fatal("Client must expose GetSecretAtPath and DeleteSecretAtPath with existing secret/delete return types")
	}
	return api
}

func TestPathContractKeyOnlyGetRejectsAmbiguity(t *testing.T) {
	c, assertCalls := pathContractClient(t, pathContractSecrets)
	_, err := c.GetSecret(context.Background(), "env", "api_key")
	assertCalls("GET /api/envs/env/secrets")
	pathContractError(t, err, 409)
}

func TestPathContractKeyOnlyDeleteRejectsAmbiguityWithoutDelete(t *testing.T) {
	c, assertCalls := pathContractClient(t, pathContractSecrets)
	_, err := c.DeleteSecret(context.Background(), "env", "api_key")
	assertCalls("GET /api/envs/env/secrets")
	pathContractError(t, err, 409)
}

func TestPathContractExplicitRootAndFolder(t *testing.T) {
	for _, index := range []int{3, 1} {
		want := pathContractSecrets[index]
		t.Run(want.ID, func(t *testing.T) {
			c, assertCalls := pathContractClient(t, pathContractSecrets)
			api := pathContractAPI(t, c)
			got, err := api.GetSecretAtPath(context.Background(), "env", "aPi_KeY", want.Path)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Error("lookup did not return the exact key/path match")
			}
			if _, err := api.DeleteSecretAtPath(context.Background(), "env", "aPi_KeY", want.Path); err != nil {
				t.Fatal(err)
			}
			assertCalls("GET /api/envs/env/secrets", "GET /api/envs/env/secrets", "DELETE /api/secrets/"+want.ID)
		})
	}
}

func TestPathContractMissingExactPathDoesNotDelete(t *testing.T) {
	for _, path := range []string{"/missing/", "/team", "/TEAM/"} {
		for _, operation := range []string{"get", "delete"} {
			t.Run(operation+path, func(t *testing.T) {
				c, assertCalls := pathContractClient(t, pathContractSecrets)
				api := pathContractAPI(t, c)
				var err error
				if operation == "get" {
					_, err = api.GetSecretAtPath(context.Background(), "env", "api_key", path)
				} else {
					_, err = api.DeleteSecretAtPath(context.Background(), "env", "api_key", path)
				}
				assertCalls("GET /api/envs/env/secrets")
				pathContractError(t, err, 404)
			})
		}
	}
}

func TestPathContractUniqueLegacyCallsStillWork(t *testing.T) {
	c, assertCalls := pathContractClient(t, pathContractSecrets[:2])
	got, err := c.GetSecret(context.Background(), "env", "api_key")
	if err != nil {
		t.Fatal(err)
	}
	if got != pathContractSecrets[1] {
		t.Error("legacy lookup did not return the unique folder secret")
	}
	if _, err := c.DeleteSecret(context.Background(), "env", "api_key"); err != nil {
		t.Fatal(err)
	}
	assertCalls("GET /api/envs/env/secrets", "GET /api/envs/env/secrets", "DELETE /api/secrets/folder")
}
