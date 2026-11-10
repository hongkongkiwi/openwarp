package openwarp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"
)

type managementCaptureTransport struct { calls int }

func (transport *managementCaptureTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls++
	return nil, errors.New("invalid base URL reached transport")
}

func TestManagementRejectsBaseURLQueryAndFragmentBeforeNetwork(t *testing.T) {
	for _, suffix := range []string{"?", "#", "?#", "?scope=admin", "#capture", "?scope=admin#capture"} {
		t.Run(suffix, func(t *testing.T) {
			transport := &managementCaptureTransport{}
			c := &Client{BaseURL:"https://example.invalid/prefix/"+suffix, Token:"private-test-token", HTTPClient:&http.Client{Transport:transport}}
			_, err := c.API(context.Background(), "POST", []string{"orgs"}, map[string]any{"name":"private"}, nil)
			if err == nil { t.Error("accepted invalid base URL") }
			if transport.calls != 0 { t.Fatalf("sent %d credential-bearing requests with invalid base URL", transport.calls) }
		})
	}
}

func TestManagementEncodingAndQuery(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/api/orgs/a%2Fb%20%3F%23%E9%9B%AA/audit" { t.Errorf("path = %s", r.URL.EscapedPath()) }
		if !reflect.DeepEqual(r.URL.Query(), url.Values{"search": {"a&b=雪 +/?#"}, "tag": {"one", "two"}}) { t.Errorf("query = %v", r.URL.Query()) }
		if r.Header.Get("Authorization") != "Bearer test-token" { t.Error("missing credential") }
		io.WriteString(w, `{"ok":true}`)
	}))
	defer s.Close()
	c := &Client{BaseURL:s.URL, Token:"test-token", HTTPClient:s.Client()}
	got, err := c.API(context.Background(), "GET", []string{"orgs", "a/b ?#雪", "audit"}, nil, url.Values{"search":{"a&b=雪 +/?#"}, "tag":{"one", "two"}})
	if err != nil { t.Fatal(err) }
	var body map[string]bool
	if err := json.Unmarshal(got, &body); err != nil || !body["ok"] { t.Fatalf("body = %s, error = %v", got, err) }
}

func TestManagementMethodsAndEmptySuccess(t *testing.T) {
	for _, method := range []string{"GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"} {
		t.Run(method, func(t *testing.T) {
			var body any
			if method == "POST" || method == "PUT" || method == "PATCH" { body = map[string]any{"name":"雪"} }
			c := mockClient(t, method, "/api/orgs/o/settings", "", 204, body)
			got, err := c.API(context.Background(), method, []string{"orgs","o","settings"}, body, nil)
			if err != nil { t.Fatal(err) }
			if len(got) != 0 && string(got) != "null" { t.Fatalf("empty response = %s", got) }
		})
	}
}

func TestManagementRejectsUnsafeInputBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, `{}`) }))
	defer s.Close()
	c := &Client{BaseURL:s.URL, Token:"test-token", HTTPClient:s.Client()}
	for _, segment := range []string{".","..","%2e","%2E%2e",".%2e","%252e%252e","a/../b","a%2f..%2fb","a%252f%252e%252e%252fb","bad%","%GG","back\\slash","bad\n","bad\x00","bad\x7f","https://example.invalid/api/me","//example.invalid/api/me"} {
		if _, err := c.API(context.Background(), "GET", []string{"orgs",segment}, nil, nil); err == nil { t.Errorf("accepted segment %q", segment) }
	}
	for _, method := range []string{"TRACE","CONNECT","BREW","GET\r\nX-Test: yes"} {
		if _, err := c.API(context.Background(), method, []string{"me"}, nil, nil); err == nil { t.Errorf("accepted method %q", method) }
	}
	if calls.Load() != 0 { t.Fatalf("sent %d unsafe requests", calls.Load()) }
}

func TestManagementPreservesErrors(t *testing.T) {
	for _, status := range []int{400,401,403,404,409,429,500,503} {
		for _, body := range []string{`{"error":"denied"}`, "provider unavailable"} {
			c := mockClient(t, "GET", "/api/orgs", body, status, nil)
			_, err := c.API(context.Background(), "GET", []string{"orgs"}, nil, nil)
			var apiErr *APIError
			if !errors.As(err, &apiErr) { t.Fatalf("expected APIError, got %v", err) }
			if apiErr.Status != status || apiErr.Body != body { t.Fatalf("error = %#v", apiErr) }
		}
	}
}

func TestManagementRejectsRedirectsWithCustomHTTPClient(t *testing.T) {
	var leaked atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1); io.WriteString(w, `{}`) }))
	defer target.Close()
	location := target.URL + "/capture"
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/capture" { leaked.Add(1); io.WriteString(w, `{}`); return }
		http.Redirect(w, r, location, 307)
	}))
	defer source.Close()
	for _, destination := range []string{target.URL+"/capture", source.URL+"/capture"} {
		location = destination
		c := &Client{BaseURL:source.URL, Token:"private-test-token", HTTPClient:source.Client()}
		if _, err := c.API(context.Background(), "POST", []string{"orgs"}, map[string]any{"name":"private"}, nil); err == nil { t.Error("redirect returned success") }
	}
	if leaked.Load() != 0 { t.Fatalf("redirect targets received %d requests", leaked.Load()) }
}
