# Entra ID app registration for the Warden API (Task 6).
#
# The control plane (controlplane/internal/authn) accepts only delegated v2
# access tokens from one tenant:
#   iss = https://login.microsoftonline.com/<tenant>/v2.0   ver = "2.0"
#   aud = this app's client ID                             scp contains warden.access
#   oid = the user's object ID (the SCIM externalId Warden looks up)
# plus sub, exp and optional nbf, signed RS256 by a key in the tenant JWKS.
# requested_access_token_version = 2 is what makes Entra issue that issuer,
# ver and a GUID audience; oid, sub and scp are default claims of every
# delegated token, so no optional claims are configured.
#
# The API never calls Entra with its own identity, so the app has no password,
# certificate or federated credential. Clients get warden.access as the
# signed-in user; the lab pre-authorizes the Azure CLI so
#   az account get-access-token --scope api://<client_id>/warden.access
# works without a consent prompt. Only users assigned to the service principal
# can get a token (app_role_assignment_required).
#
# Lab rules (docs/identity.md): the display name starts with warden-lab-, the
# tags carry project=warden, the signed-in user is the only owner, and the
# objects are destroyed after the test. State goes outside the repo:
#   terraform init -backend-config=path=<outside the repo>/idp.tfstate

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "= 3.10.0"
    }
  }
  backend "local" {}
}

# Authenticates with the Azure CLI login; tenant comes from that login.
provider "azuread" {}

variable "ttl" {
  description = "UTC time after which the lab objects must be gone, e.g. 2026-11-11T06:00:00Z."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", var.ttl))
    error_message = "ttl must be a UTC timestamp like 2026-11-11T06:00:00Z."
  }
}

variable "preauthorized_client_ids" {
  description = "Client IDs allowed to request warden.access without user consent. Lab default: the Azure CLI."
  type        = set(string)
  default     = ["04b07795-8ddb-461a-bbee-02f9e1bf7b46"]
}

data "azuread_client_config" "current" {}

locals {
  # Fixed so that a re-apply keeps the scope ID clients already reference.
  scope_id = "eb84a779-51cc-4ba7-af01-55dc258737a7"
  tags     = ["project=warden", "owner=warden-lab", "ttl=${var.ttl}", "est_usd_per_hour=0"]
}

resource "azuread_application" "api" {
  display_name                   = "warden-lab-api"
  sign_in_audience               = "AzureADMyOrg"
  owners                         = [data.azuread_client_config.current.object_id]
  tags                           = local.tags
  fallback_public_client_enabled = false

  api {
    requested_access_token_version = 2

    oauth2_permission_scope {
      id                         = local.scope_id
      value                      = "warden.access"
      type                       = "User"
      enabled                    = true
      admin_consent_display_name = "Use Warden"
      admin_consent_description  = "Create and read Warden runs as the signed-in user."
      user_consent_display_name  = "Use Warden"
      user_consent_description   = "Create and read Warden runs as you."
    }
  }
}

# api://<client_id> cannot be set on the application itself (it does not know
# its client ID before creation).
resource "azuread_application_identifier_uri" "api" {
  application_id = azuread_application.api.id
  identifier_uri = "api://${azuread_application.api.client_id}"
}

resource "azuread_application_pre_authorized" "clients" {
  for_each             = var.preauthorized_client_ids
  application_id       = azuread_application.api.id
  authorized_client_id = each.value
  permission_ids       = [local.scope_id]
}

resource "azuread_service_principal" "api" {
  client_id                    = azuread_application.api.client_id
  owners                       = [data.azuread_client_config.current.object_id]
  tags                         = local.tags
  app_role_assignment_required = true
}

# What the control plane needs (WARDEN_OIDC_*), and the scope clients request.
output "oidc_issuer" {
  value = "https://login.microsoftonline.com/${data.azuread_client_config.current.tenant_id}/v2.0"
}

output "oidc_jwks_url" {
  value = "https://login.microsoftonline.com/${data.azuread_client_config.current.tenant_id}/discovery/v2.0/keys"
}

output "oidc_audience" {
  value = azuread_application.api.client_id
}

output "scope" {
  value = "api://${azuread_application.api.client_id}/warden.access"
}

output "application_object_id" {
  value = azuread_application.api.object_id
}

output "service_principal_object_id" {
  value = azuread_service_principal.api.object_id
}
