package provider_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hongkongkiwi/terraform-provider-openwarp/internal/provider"
)

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
