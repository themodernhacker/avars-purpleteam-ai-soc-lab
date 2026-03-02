# ==============================================================================
# Physical & Operational Security (Provider-Compatible Refactor)
# ==============================================================================

variable "deploy_physical_security" {
  description = "Deploy physical/operational security telemetry resources"
  type        = bool
  default     = true
}

resource "random_string" "physical_sec_suffix" {
  count   = var.deploy_physical_security ? 1 : 0
  length  = 6
  special = false
  upper   = false
}

resource "azurerm_storage_account" "physical_access_logs" {
  count                    = var.deploy_physical_security ? 1 : 0
  name                     = "physec${random_string.physical_sec_suffix[0].result}"
  resource_group_name      = azurerm_resource_group.avars.name
  location                 = azurerm_resource_group.avars.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
  tags = merge(local.common_tags, {
    Module = "physical-security"
    Scope  = "badge-and-environment-logs"
  })
}

resource "azurerm_storage_container" "physical_badge_events" {
  count                 = var.deploy_physical_security ? 1 : 0
  name                  = "badge-events"
  storage_account_name  = azurerm_storage_account.physical_access_logs[0].name
  container_access_type = "private"
}

resource "azurerm_iothub" "physical_env_iothub" {
  count               = var.deploy_physical_security ? 1 : 0
  name                = "iothub-${local.resource_prefix}-${random_string.physical_sec_suffix[0].result}"
  resource_group_name = azurerm_resource_group.avars.name
  location            = azurerm_resource_group.avars.location

  sku {
    name     = "S1"
    capacity = 1
  }

  tags = merge(local.common_tags, {
    Module = "physical-security"
    Scope  = "environment-monitoring"
  })
}

resource "azurerm_log_analytics_saved_search" "physical_access_anomalies" {
  count                      = var.deploy_physical_security ? 1 : 0
  name                       = "PhysicalAccessAnomalies"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.avars.id
  category                   = "Security"
  display_name               = "Physical Access Anomalies"

  query = <<-KQL
    AzureDiagnostics
    | where msg_s contains "badge" or msg_s contains "door" or msg_s contains "physical"
    | summarize Events=count() by bin(TimeGenerated, 15m)
    | where Events > 20
  KQL

  function_alias = "GetPhysicalAccessAnomalies"
}

output "physical_security_iothub_name" {
  description = "IoT Hub for physical environmental telemetry"
  value       = var.deploy_physical_security ? azurerm_iothub.physical_env_iothub[0].name : null
}
