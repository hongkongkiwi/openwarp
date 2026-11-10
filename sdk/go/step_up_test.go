package openwarp

import (
    "context"
    "io"
    "net/http"
    "strings"
    "testing"
)

type stepUpTransport struct { calls int; grant string }
func (transport *stepUpTransport) RoundTrip(request *http.Request) (*http.Response, error) {
    transport.calls++
    transport.grant = request.Header.Get("X-OpenWarp-Step-Up")
    if request.Header.Get("Authorization") != "Bearer original-bearer" { panic("bearer credential changed") }
    return &http.Response{StatusCode:200, Header:make(http.Header), Body:io.NopCloser(strings.NewReader(`{"ok":true}`)), Request:request}, nil
}

func TestExplicitStepUpPreservesBearerAndExistingAPICalls(t *testing.T) {
    transport := &stepUpTransport{}
    client := &Client{BaseURL:"https://example.invalid", Token:"original-bearer", HTTPClient:&http.Client{Transport:transport}}
    if _, err := client.API(context.Background(), "POST", []string{"orgs"}, map[string]any{}, nil, "stepupg_safe-grant"); err != nil { t.Fatal(err) }
    if transport.calls != 1 || transport.grant != "stepupg_safe-grant" { t.Fatalf("calls=%d, grant=%q",transport.calls,transport.grant) }
    if _, err := client.API(context.Background(), "GET", []string{"me"}, nil, nil); err != nil { t.Fatal(err) }
    if transport.calls != 2 || transport.grant != "" { t.Fatal("grant persisted into compatible old API call") }
}

func TestInvalidStepUpFailsBeforeTransport(t *testing.T) {
    cases := [][]string{{""},{"x\r\nAuthorization: forged"},{"x\x00"},{"x\x1f"},{"x\x7f"},{"é"},{strings.Repeat("x",513)},{"one","two"}}
    for _, grants := range cases {
        transport := &stepUpTransport{}
        client := &Client{BaseURL:"https://example.invalid", Token:"original-bearer", HTTPClient:&http.Client{Transport:transport}}
        if _, err := client.API(context.Background(), "POST", []string{"orgs"}, nil, nil, grants...); err == nil { t.Errorf("accepted grants %q",grants) }
        if transport.calls != 0 { t.Errorf("invalid grants reached transport: %q",grants) }
    }
}
