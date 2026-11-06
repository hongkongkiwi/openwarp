package client_test

import (
	"context"
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

	"github.com/hongkongkiwi/terraform-provider-openwarp/internal/client"
)

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func startServer(t *testing.T) (string, <-chan string) {
	t.Helper()
	bin := os.Getenv("OPENWARP_BIN")
	if bin == "" {
		bin = "../../../target/debug/openwarp-server"
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("server binary not found at %s; build it or set OPENWARP_BIN", bin)
	}
	// Registration sends a verification link. Capture it through the mail
	// webhook provider so the test exercises the real signup flow.
	inbox := make(chan string, 4)
	mail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var message struct {
			Text string `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		select {
		case inbox <- message.Text:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(mail.Close)

	dir := t.TempDir()
	port := freePort(t)
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	command := exec.Command(bin)
	env := make([]string, 0, len(os.Environ())+8)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "OPENWARP_MASTER_KEY=") || strings.HasPrefix(kv, "REDIS_URL=") || strings.HasPrefix(kv, "OPENWARP_ENV=") ||
			strings.HasPrefix(kv, "OPENWARP_EMAIL_") || strings.HasPrefix(kv, "OPENWARP_SMTP_") ||
			strings.HasPrefix(kv, "OPENWARP_RESEND_") || strings.HasPrefix(kv, "OPENWARP_SENDGRID_") ||
			strings.HasPrefix(kv, "OPENWARP_MAILGUN_") || strings.HasPrefix(kv, "OPENWARP_POSTMARK_") ||
			strings.HasPrefix(kv, "OPENWARP_CLOUDFLARE_EMAIL_") {
			continue
		}
		env = append(env, kv)
	}
	command.Env = append(env,
		"DATABASE_URL=sqlite://"+filepath.Join(dir, "provider.db"),
		"ADDR=127.0.0.1:"+strconv.Itoa(port),
		"OPENWARP_PUBLIC_URL="+base,
		"OPENWARP_EMAIL_PROVIDER=webhook",
		"OPENWARP_EMAIL_WEBHOOK="+mail.URL,
		"OPENWARP_EMAIL_FROM=no-reply@test.invalid",
		"TOKIO_WORKER_THREADS=2",
	)
	if err := command.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
	})
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get(base + "/health")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return base, inbox
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("server did not become healthy")
	return "", nil
}

func verificationLink(t *testing.T, text string) string {
	t.Helper()
	const marker = "/api/auth/verify?token="
	start := strings.Index(text, marker)
	if start < 0 {
		t.Fatalf("verification link missing from mail: %q", text)
	}
	rest := text[start+len(marker):]
	end := strings.IndexAny(rest, " \t\r\n\"'<>")
	if end < 0 {
		end = len(rest)
	}
	return marker + rest[:end]
}

func TestClientRoundTrip(t *testing.T) {
	base, inbox := startServer(t)
	ctx := context.Background()
	api := client.New(base, "")
	email, password := "provider@test.invalid", "provider-password-1"
	token, err := api.Register(ctx, email, password)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if token == "" {
		var text string
		select {
		case text = <-inbox:
		case <-time.After(10 * time.Second):
			t.Fatal("verification mail did not arrive")
		}
		verify, err := http.Get(base + verificationLink(t, text))
		if err != nil {
			t.Fatalf("verify email: %v", err)
		}
		verify.Body.Close()
		if verify.StatusCode != http.StatusOK {
			t.Fatalf("verify email: HTTP %d", verify.StatusCode)
		}
		token, err = api.Login(ctx, email, password)
		if err != nil {
			t.Fatalf("login: %v", err)
		}
	}
	if token == "" {
		t.Fatal("no session token after registration")
	}
	api.Token = token

	orgs, err := api.ListOrgs(ctx)
	if err != nil || len(orgs) == 0 {
		t.Fatalf("list orgs: %v", err)
	}
	org := orgs[0].ID

	appID, err := api.CreateApp(ctx, org, "tf-app")
	if err != nil {
		t.Fatalf("create app: %v", err)
	}
	envs, err := api.ListEnvs(ctx, appID)
	if err != nil || len(envs) != 3 {
		t.Fatalf("list envs: %v (got %d)", err, len(envs))
	}
	env := envs[0].ID

	yes, no := true, false
	if err := api.SetEnvPolicy(ctx, env, &yes, &no); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	envs, _ = api.ListEnvs(ctx, appID)
	if envs[0].Restricted != 1 {
		t.Fatalf("policy not applied: %+v", envs[0])
	}

	if err := api.DeploySecret(ctx, env, client.SecretInput{Key: "API_KEY", Value: "v1", Tags: "team=a"}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	secrets, err := api.ListSecrets(ctx, env)
	if err != nil || len(secrets) != 1 {
		t.Fatalf("list secrets: %v (got %d)", err, len(secrets))
	}
	if secrets[0].Key != "API_KEY" || secrets[0].Value == nil || *secrets[0].Value != "v1" || secrets[0].Tags != "team=a" {
		t.Fatalf("unexpected secret: %+v", secrets[0])
	}
	if err := api.DeploySecret(ctx, env, client.SecretInput{Key: "API_KEY", Value: "v2", Tags: "team=a"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	secrets, _ = api.ListSecrets(ctx, env)
	if secrets[0].Value == nil || *secrets[0].Value != "v2" {
		t.Fatalf("update not applied: %+v", secrets[0])
	}
	if err := api.DeleteSecret(ctx, secrets[0].ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	secrets, _ = api.ListSecrets(ctx, env)
	if len(secrets) != 0 {
		t.Fatalf("secret still present after delete: %+v", secrets)
	}

	created, err := api.CreateToken(ctx, appID, "ci", env)
	if err != nil || created.Token == "" {
		t.Fatalf("create token: %v", err)
	}
	tokens, _ := api.ListTokens(ctx, appID)
	found := false
	for _, item := range tokens {
		if item.ID == created.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("token not listed: %+v", tokens)
	}
	if err := api.RevokeToken(ctx, created.ID); err != nil {
		t.Fatalf("revoke token: %v", err)
	}

	if err := api.DeleteApp(ctx, appID); err != nil {
		t.Fatalf("delete app: %v", err)
	}
	apps, _ := api.ListApps(ctx, org)
	for _, app := range apps {
		if app.ID == appID {
			t.Fatalf("app still present after delete")
		}
	}
}
