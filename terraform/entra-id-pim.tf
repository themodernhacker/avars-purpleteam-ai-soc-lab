# ==============================================================================
# Identity Controls (Entra/PIM-Compatible Terraform Refactor)
# ==============================================================================

variable "enable_identity_controls" {
  description = "Deploy identity-first controls for automation and least privilege"
  type        = bool
  default     = true
}

resource "azurerm_user_assigned_identity" "avars_automation_identity" {
  count               = var.enable_identity_controls ? 1 : 0
  name                = "${local.resource_prefix}-automation-identity"
  resource_group_name = azurerm_resource_group.avars.name
  location            = azurerm_resource_group.avars.location
  tags = merge(local.common_tags, {
    Module = "identity-controls"
    Scope  = "least-privilege-automation"
  })
}

resource "azurerm_role_assignment" "automation_reader_rg" {
  count                = var.enable_identity_controls ? 1 : 0
  scope                = azurerm_resource_group.avars.id
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.avars_automation_identity[0].principal_id
}

resource "azurerm_role_assignment" "automation_log_analytics_reader" {
  count                = var.enable_identity_controls ? 1 : 0
  scope                = azurerm_log_analytics_workspace.avars.id
  role_definition_name = "Log Analytics Reader"
  principal_id         = azurerm_user_assigned_identity.avars_automation_identity[0].principal_id
}

resource "azurerm_key_vault_access_policy" "automation_identity_policy" {
  count        = var.enable_identity_controls ? 1 : 0
  key_vault_id = azurerm_key_vault.avars.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_user_assigned_identity.avars_automation_identity[0].principal_id

  secret_permissions = [
    "Get",
    "List"
  ]

  certificate_permissions = [
    "Get",
    "List"
  ]

  key_permissions = [
    "Get",
    "List"
  ]
}

output "automation_identity_client_id" {
  description = "Client ID of automation managed identity"
  value       = var.enable_identity_controls ? azurerm_user_assigned_identity.avars_automation_identity[0].client_id : null
}
