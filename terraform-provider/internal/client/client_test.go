package client_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
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

func startServer(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("OPENWARP_BIN")
	if bin == "" {
		bin = "../../../target/debug/openwarp-server"
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("server binary not found at %s; build it or set OPENWARP_BIN", bin)
	}
	dir := t.TempDir()
	port := freePort(t)
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	command := exec.Command(bin)
	env := make([]string, 0, len(os.Environ())+4)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "OPENWARP_MASTER_KEY=") || strings.HasPrefix(kv, "REDIS_URL=") || strings.HasPrefix(kv, "OPENWARP_ENV=") {
			continue
		}
		env = append(env, kv)
	}
	command.Env = append(env,
		"DATABASE_URL=sqlite://"+filepath.Join(dir, "provider.db"),
		"ADDR=127.0.0.1:"+strconv.Itoa(port),
		"OPENWARP_PUBLIC_URL="+base,
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
				return base
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("server did not become healthy")
	return ""
}

func TestClientRoundTrip(t *testing.T) {
	base := startServer(t)
	ctx := context.Background()
	api := client.New(base, "")
	token, err := api.Register(ctx, "provider@test.invalid", "provider-password-1")
	if err != nil {
		t.Fatalf("register: %v", err)
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
