package openwarp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"sync"
	"testing"
)

var paginationFirst = Secret{ID: "first", Key: "API_KEY", Path: "/", Value: "dummy-first"}
var paginationLater = Secret{ID: "later", Key: "API_KEY", Path: "/team/", Value: "dummy-later"}
var paginationOther = Secret{ID: "other", Key: "OTHER", Path: "/", Value: "dummy-other"}
var paginationOther2 = Secret{ID: "other2", Key: "OTHER2", Path: "/", Value: "dummy-other2"}

func paginationClient(t *testing.T, first, later []Secret, mode string) (*Client, func([]int, string)) {
	t.Helper()
	var mu sync.Mutex
	var offsets []int
	var deletes []string
	pages := map[int]map[string]any{
		0: {"secrets": first, "total": 4, "limit": 2, "offset": 0},
		2: {"secrets": later, "total": 4, "limit": 2, "offset": 2},
	}
	switch mode {
	case "legacy":
		pages[0] = map[string]any{"secrets": first}
	case "partial":
		pages[0] = map[string]any{"secrets": first, "total": 4}
	case "stalled":
		pages[2]["offset"] = 0
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer pagination-dummy-token" {
			t.Error("request omitted fixture bearer token")
			w.WriteHeader(401)
			return
		}
		if r.Method == "GET" && r.URL.Path == "/api/envs/env/secrets" {
			offset := 0
			if raw := r.URL.Query().Get("offset"); raw != "" {
				var err error
				offset, err = strconv.Atoi(raw)
				if err != nil { t.Error("invalid requested offset"); w.WriteHeader(400); return }
			}
			offsets = append(offsets, offset)
			for key := range r.URL.Query() {
				if key != "offset" && key != "limit" { t.Errorf("unexpected query parameter %q", key) }
			}
			if len(offsets) > 3 { w.WriteHeader(500); _, _ = w.Write([]byte(`{"error":"fixture pagination request budget exceeded"}`)); return }
			if page, ok := pages[offset]; ok { _ = json.NewEncoder(w).Encode(page); return }
		}
		if r.Method == "DELETE" && (r.RequestURI == "/api/secrets/first" || r.RequestURI == "/api/secrets/later") {
			deletes = append(deletes, r.RequestURI)
			_, _ = w.Write([]byte(`{"deleted":true}`))
			return
		}
		t.Errorf("unexpected route: %s %s", r.Method, r.RequestURI)
		w.WriteHeader(404)
	}))
	t.Cleanup(server.Close)
	assertCalls := func(wantOffsets []int, deleted string) {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		if !reflect.DeepEqual(offsets, wantOffsets) { t.Errorf("GET offsets = %v; want %v", offsets, wantOffsets) }
		var wantDeletes []string
		if deleted != "" { wantDeletes = []string{"/api/secrets/" + deleted} }
		if !reflect.DeepEqual(deletes, wantDeletes) { t.Errorf("DELETE routes = %v; want %v", deletes, wantDeletes) }
	}
	return &Client{BaseURL: server.URL, Token: "pagination-dummy-token", HTTPClient: server.Client()}, assertCalls
}

func TestPaginationContractDuplicateAcrossPagesRejectsGetAndDelete(t *testing.T) {
	for _, operation := range []string{"get", "delete"} {
		t.Run(operation, func(t *testing.T) {
			c, assertCalls := paginationClient(t, []Secret{paginationFirst, paginationOther}, []Secret{paginationLater, paginationOther2}, "valid")
			var err error
			if operation == "get" { _, err = c.GetSecret(context.Background(), "env", "api_key") } else { _, err = c.DeleteSecret(context.Background(), "env", "api_key") }
			assertCalls([]int{0, 2}, "")
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.Status != 409 { t.Errorf("expected ambiguity APIError 409, got %v", err) }
		})
	}
}

func TestPaginationContractExactPathTargetOnLaterPage(t *testing.T) {
	for _, operation := range []string{"get", "delete"} {
		t.Run(operation, func(t *testing.T) {
			c, assertCalls := paginationClient(t, []Secret{paginationOther, paginationOther2}, []Secret{paginationLater, paginationFirst}, "valid")
			if operation == "get" {
				got, err := c.GetSecretAtPath(context.Background(), "env", "api_key", "/team/")
				assertCalls([]int{0, 2}, "")
				if err != nil { t.Fatal(err) }
				if got != paginationLater { t.Error("lookup did not return the later-page exact path target") }
			} else {
				_, err := c.DeleteSecretAtPath(context.Background(), "env", "api_key", "/team/")
				assertCalls([]int{0, 2}, "later")
				if err != nil { t.Fatal(err) }
			}
		})
	}
}

func TestPaginationContractInvalidMetadataFailsClosedAndLegacyWorks(t *testing.T) {
	t.Run("legacy", func(t *testing.T) {
		c, assertCalls := paginationClient(t, []Secret{paginationFirst}, []Secret{}, "legacy")
		got, err := c.GetSecret(context.Background(), "env", "api_key")
		if err != nil { t.Fatal(err) }
		if got != paginationFirst { t.Error("legacy no-metadata lookup changed") }
		if _, err := c.DeleteSecret(context.Background(), "env", "api_key"); err != nil { t.Fatal(err) }
		assertCalls([]int{0, 0}, "first")
	})
	for _, mode := range []string{"partial", "stalled"} {
		for _, operation := range []string{"get", "delete"} {
			t.Run(mode+"/"+operation, func(t *testing.T) {
				c, assertCalls := paginationClient(t, []Secret{paginationFirst, paginationOther}, []Secret{paginationOther, paginationOther2}, mode)
				var err error
				if operation == "get" { _, err = c.GetSecret(context.Background(), "env", "api_key") } else { _, err = c.DeleteSecret(context.Background(), "env", "api_key") }
				want := []int{0}
				if mode == "stalled" { want = []int{0, 2} }
				assertCalls(want, "")
				if err == nil { t.Error("invalid pagination accepted an incomplete selection") }
			})
		}
	}
}
