package provider_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hongkongkiwi/terraform-provider-openwarp/internal/provider"
)

// TestMain starts a disposable server when TF_ACC is set and the caller did
// not provide an instance. This keeps the acceptance suite runnable in CI
// without a pre-seeded account. An explicitly configured host always wins.
func TestMain(m *testing.M) {
	if os.Getenv("TF_ACC") == "" || os.Getenv("OPENWARP_HOST") != "" {
		os.Exit(m.Run())
	}
	cleanup, err := startAcceptanceServer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "acceptance server: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func startAcceptanceServer() (func(), error) {
	bin := os.Getenv("OPENWARP_BIN")
	if bin == "" {
		bin = "../../../target/debug/openwarp-server"
	}
	if _, err := os.Stat(bin); err != nil {
		return nil, fmt.Errorf("server binary not found at %s; build it or set OPENWARP_BIN", bin)
	}
	inbox := make(chan string, 4)
	mail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var message struct {
			Text string `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&message); err == nil {
			select {
			case inbox <- message.Text:
			default:
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		mail.Close()
		return nil, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	dir, err := os.MkdirTemp("", "openwarp-provider-acc-*")
	if err != nil {
		mail.Close()
		return nil, err
	}
	command := exec.Command(bin)
	env := make([]string, 0, len(os.Environ())+8)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "OPENWARP_MASTER_KEY=") || strings.HasPrefix(kv, "REDIS_URL=") ||
			strings.HasPrefix(kv, "OPENWARP_ENV=") || strings.HasPrefix(kv, "OPENWARP_EMAIL_") ||
			strings.HasPrefix(kv, "OPENWARP_SMTP_") || strings.HasPrefix(kv, "OPENWARP_RESEND_") ||
			strings.HasPrefix(kv, "OPENWARP_SENDGRID_") || strings.HasPrefix(kv, "OPENWARP_MAILGUN_") ||
			strings.HasPrefix(kv, "OPENWARP_POSTMARK_") || strings.HasPrefix(kv, "OPENWARP_CLOUDFLARE_EMAIL_") {
			continue
		}
		env = append(env, kv)
	}
	command.Env = append(env,
		"DATABASE_URL=sqlite://"+filepath.Join(dir, "acceptance.db"),
		"ADDR=127.0.0.1:"+strconv.Itoa(port),
		"OPENWARP_PUBLIC_URL="+base,
		"OPENWARP_EMAIL_PROVIDER=webhook",
		"OPENWARP_EMAIL_WEBHOOK="+mail.URL,
		"OPENWARP_EMAIL_FROM=no-reply@test.invalid",
		"TOKIO_WORKER_THREADS=2",
	)
	if err := command.Start(); err != nil {
		mail.Close()
		os.RemoveAll(dir)
		return nil, fmt.Errorf("start server: %w", err)
	}
	cleanup := func() {
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
		mail.Close()
		os.RemoveAll(dir)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get(base + "/health")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	call := func(method, path string, body any, out any) error {
		var payload *bytes.Reader
		if body == nil {
			payload = bytes.NewReader(nil)
		} else {
			encoded, err := json.Marshal(body)
			if err != nil {
				return err
			}
			payload = bytes.NewReader(encoded)
		}
		req, err := http.NewRequest(method, base+path, payload)
		if err != nil {
			return err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := client.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return fmt.Errorf("%s %s: HTTP %d", method, path, res.StatusCode)
		}
		if out != nil {
			return json.NewDecoder(res.Body).Decode(out)
		}
		return nil
	}
	var registered struct {
		OrgID              string `json:"org_id"`
		VerificationNeeded bool   `json:"verification_required"`
	}
	email, password := "acceptance@test.invalid", "acceptance-password-1"
	if err := call(http.MethodPost, "/api/auth/register", map[string]string{"email": email, "password": password}, &registered); err != nil {
		cleanup()
		return nil, fmt.Errorf("register: %w", err)
	}
	if registered.VerificationNeeded {
		var text string
		select {
		case text = <-inbox:
		case <-time.After(10 * time.Second):
			cleanup()
			return nil, fmt.Errorf("verification mail did not arrive")
		}
		const marker = "/api/auth/verify?token="
		start := strings.Index(text, marker)
		if start < 0 {
			cleanup()
			return nil, fmt.Errorf("verification link missing from mail: %q", text)
		}
		rest := text[start+len(marker):]
		end := strings.IndexAny(rest, " \t\r\n\"'<>")
		if end < 0 {
			end = len(rest)
		}
		if err := call(http.MethodGet, marker+rest[:end], nil, nil); err != nil {
			cleanup()
			return nil, fmt.Errorf("verify email: %w", err)
		}
	}
	var login struct {
		Token string `json:"token"`
	}
	if err := call(http.MethodPost, "/api/auth/login", map[string]string{"email": email, "password": password}, &login); err != nil {
		cleanup()
		return nil, fmt.Errorf("login: %w", err)
	}
	if login.Token == "" || registered.OrgID == "" {
		cleanup()
		return nil, fmt.Errorf("registration did not yield a token and organisation")
	}
	os.Setenv("OPENWARP_HOST", base)
	os.Setenv("OPENWARP_TOKEN", login.Token)
	os.Setenv("OPENWARP_TEST_ORG_ID", registered.OrgID)
	return cleanup, nil
}

var testFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"openwarp": providerserver.NewProtocol6WithError(provider.New("test")()),
}

func preCheck(t *testing.T) {
	t.Helper()
	for _, key := range []string{"OPENWARP_HOST", "OPENWARP_TOKEN", "OPENWARP_TEST_ORG_ID"} {
		if os.Getenv(key) == "" {
			t.Skipf("%s must be set for acceptance tests", key)
		}
	}
}

func baseConfig() string {
	return `provider "openwarp" {}
`
}

func orgID() string { return os.Getenv("OPENWARP_TEST_ORG_ID") }

func TestAccApp_basic(t *testing.T) {
	config := func(name string) string {
		return baseConfig() + fmt.Sprintf(`
resource "openwarp_app" "test" {
  org_id = %q
  name   = %q
}
`, orgID(), name)
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { preCheck(t) },
		ProtoV6ProviderFactories: testFactories,
		Steps: []resource.TestStep{
			{
				Config: config("acc-app"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("openwarp_app.test", "name", "acc-app"),
					resource.TestCheckResourceAttrSet("openwarp_app.test", "id"),
				),
			},
			{
				Config: config("acc-app-renamed"),
				Check:  resource.TestCheckResourceAttr("openwarp_app.test", "name", "acc-app-renamed"),
			},
			{
				ResourceName:      "openwarp_app.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccSecret_basic(t *testing.T) {
	config := func(value string) string {
		return baseConfig() + fmt.Sprintf(`
resource "openwarp_app" "test" {
  org_id = %q
  name   = "acc-secret-app"
}

resource "openwarp_environment" "test" {
  app_id     = openwarp_app.test.id
  name       = "qa"
  restricted = true
}

resource "openwarp_secret" "test" {
  env_id = openwarp_environment.test.id
  key    = "API_KEY"
  value  = %q
  tags   = "team=a"
  type   = "config"
}

data "openwarp_secret" "read" {
  env_id     = openwarp_environment.test.id
  key        = "API_KEY"
  depends_on = [openwarp_secret.test]
}
`, orgID(), value)
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { preCheck(t) },
		ProtoV6ProviderFactories: testFactories,
		Steps: []resource.TestStep{
			{
				Config: config("v1"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("openwarp_environment.test", "restricted", "true"),
					resource.TestCheckResourceAttr("openwarp_secret.test", "key", "API_KEY"),
					resource.TestCheckResourceAttr("openwarp_secret.test", "value", "v1"),
					resource.TestCheckResourceAttr("openwarp_secret.test", "type", "config"),
					resource.TestCheckResourceAttr("openwarp_secret.test", "tags", "team=a"),
					resource.TestCheckResourceAttr("openwarp_secret.test", "path", "/"),
					resource.TestCheckResourceAttr("data.openwarp_secret.read", "value", "v1"),
				),
			},
			{
				Config: config("v2"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("openwarp_secret.test", "value", "v2"),
					resource.TestCheckResourceAttr("data.openwarp_secret.read", "value", "v2"),
				),
			},
			{
				ResourceName:      "openwarp_secret.test",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: func(state *terraform.State) (string, error) {
					rs, ok := state.RootModule().Resources["openwarp_secret.test"]
					if !ok {
						return "", fmt.Errorf("openwarp_secret.test not found in state")
					}
					return fmt.Sprintf("%s:/:%s", rs.Primary.Attributes["env_id"], rs.Primary.Attributes["key"]), nil
				},
			},
		},
	})
}

func TestAccServiceToken_basic(t *testing.T) {
	config := baseConfig() + fmt.Sprintf(`
resource "openwarp_app" "test" {
  org_id = %q
  name   = "acc-token-app"
}

resource "openwarp_environment" "test" {
  app_id = openwarp_app.test.id
  name   = "ci"
}

resource "openwarp_service_token" "test" {
  app_id = openwarp_app.test.id
  env_id = openwarp_environment.test.id
  name   = "ci-token"
}
`, orgID())
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { preCheck(t) },
		ProtoV6ProviderFactories: testFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("openwarp_service_token.test", "id"),
					resource.TestCheckResourceAttrSet("openwarp_service_token.test", "token"),
					resource.TestCheckResourceAttr("openwarp_service_token.test", "name", "ci-token"),
				),
			},
			{
				ResourceName:            "openwarp_service_token.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"token"},
			},
		},
	})
}
