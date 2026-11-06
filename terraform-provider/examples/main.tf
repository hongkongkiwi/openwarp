terraform {
  required_providers {
    openwarp = {
      source  = "hongkongkiwi/openwarp"
      version = ">= 0.1.0"
    }
  }
}

variable "openwarp_host" { type = string }
variable "openwarp_token" {
  type      = string
  sensitive = true
}
variable "org_id" { type = string }
variable "database_url" {
  type      = string
  sensitive = true
}

provider "openwarp" {
  host  = var.openwarp_host
  token = var.openwarp_token
}

resource "openwarp_app" "billing" {
  org_id = var.org_id
  name   = "billing-api"
}

resource "openwarp_environment" "production" {
  app_id           = openwarp_app.billing.id
  name             = "Production"
  restricted       = true
  require_approval = true
}

resource "openwarp_secret" "database_url" {
  env_id = openwarp_environment.production.id
  key    = "DATABASE_URL"
  value  = var.database_url
  tags   = "owner=platform"
}

data "openwarp_secret" "database_url" {
  env_id     = openwarp_environment.production.id
  key        = "DATABASE_URL"
  depends_on = [openwarp_secret.database_url]
}

resource "openwarp_service_token" "ci" {
  app_id = openwarp_app.billing.id
  env_id = openwarp_environment.production.id
  name   = "ci"
}

output "ci_token" {
  value     = openwarp_service_token.ci.token
  sensitive = true
}

output "database_url_readback" {
  value     = data.openwarp_secret.database_url.value
  sensitive = true
}
