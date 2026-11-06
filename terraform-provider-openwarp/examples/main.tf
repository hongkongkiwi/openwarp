terraform {
  required_providers {
    openwarp = {
      source = "hongkongkiwi/openwarp"
    }
  }
}

# Set OPENWARP_BASE_URL and OPENWARP_TOKEN in the environment.
# The source address is a scaffold convention, not a published registry entry.
provider "openwarp" {}

variable "app_id" {
  type = string
}

variable "env_id" {
  type = string
}

variable "secret_value" {
  type      = string
  sensitive = true
}

resource "openwarp_secret" "example" {
  app_id  = var.app_id
  env_id  = var.env_id
  key     = "EXAMPLE_TOKEN"
  value   = var.secret_value
  path    = "/"
  type    = "secret"
  comment = "Managed by Terraform"
}

data "openwarp_secret" "example" {
  env_id     = var.env_id
  key        = openwarp_secret.example.key
  depends_on = [openwarp_secret.example]
}
