# Main Terraform Configuration for Project A.V.A.R.S

terraform {
  required_version = ">= 1.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.50"
    }
  }

  # Uncomment for remote state management
  # backend "azurerm" {
  #   resource_group_name  = "avars-terraform-state"
  #   storage_account_name = "avarsterraformstate"
  #   container_name       = "tfstate"
  #   key                  = "avars.tfstate"
  # }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
  }

  subscription_id = var.azure_subscription_id
  tenant_id       = var.azure_tenant_id
}

# Local variables for consistent naming
locals {
  resource_prefix = "${var.project_name}-${var.environment}"

  hub_vnet_name    = "${local.resource_prefix}-hub-vnet"
  spoke1_vnet_name = "${local.resource_prefix}-spoke1-vnet"
  spoke2_vnet_name = "${local.resource_prefix}-spoke2-vnet"

  log_analytics_workspace_name = "${local.resource_prefix}-law"
  sentinel_name                = "${local.resource_prefix}-sentinel"
  firewall_name                = "${local.resource_prefix}-fw"

  common_tags = merge(
    var.tags,
    {}
  )
}

# ============================================================
# Resource Group
# ============================================================
resource "azurerm_resource_group" "avars" {
  name     = var.resource_group_name
  location = var.location
  tags     = local.common_tags
}

# ============================================================
# Log Analytics Workspace (Centralized Logging)
# ============================================================
resource "azurerm_log_analytics_workspace" "avars" {
  name                = local.log_analytics_workspace_name
  location            = azurerm_resource_group.avars.location
  resource_group_name = azurerm_resource_group.avars.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_analytics_retention_days

  tags = local.common_tags
}

# ============================================================
# Microsoft Sentinel
# ============================================================
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "avars" {
  count        = var.sentinel_enabled ? 1 : 0
  workspace_id = azurerm_log_analytics_workspace.avars.id

  depends_on = [azurerm_log_analytics_workspace.avars]
}

# ============================================================
# Diagnostic Settings for Activity Logs
# ============================================================
resource "azurerm_monitor_diagnostic_setting" "resourcegroup" {
  count                      = var.deploy_resourcegroup_diagnostics ? 1 : 0
  name                       = "${var.resource_group_name}-diag"
  target_resource_id         = azurerm_resource_group.avars.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.avars.id

  enabled_log {
    category = "Administrative"
  }

  enabled_log {
    category = "Security"
  }

  enabled_log {
    category = "ServiceHealth"
  }

  enabled_log {
    category = "Alert"
  }

  enabled_log {
    category = "Recommendation"
  }

  enabled_log {
    category = "Policy"
  }

  metric {
    category = "AllMetrics"
    enabled  = false
  }
}

# ============================================================
# Key Vault for Secrets Management
# ============================================================
resource "azurerm_key_vault" "avars" {
  name                        = "${local.resource_prefix}-kv-${random_string.keyvault_suffix.result}"
  location                    = azurerm_resource_group.avars.location
  resource_group_name         = azurerm_resource_group.avars.name
  tenant_id                   = var.azure_tenant_id
  sku_name                    = "standard"
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false
  enabled_for_deployment      = true
  enabled_for_disk_encryption = true

  tags = local.common_tags
}

resource "azurerm_key_vault_access_policy" "terraform_current_identity_policy" {
  key_vault_id = azurerm_key_vault.avars.id
  tenant_id    = var.azure_tenant_id
  object_id    = data.azurerm_client_config.current.object_id

  key_permissions = [
    "Get", "List", "Create", "Delete", "Recover", "Backup", "Restore"
  ]

  secret_permissions = [
    "Get", "List", "Set", "Delete", "Recover", "Backup", "Restore"
  ]

  certificate_permissions = [
    "Get", "List", "Create", "Delete", "Recover", "Backup", "Restore", "Import"
  ]
}

# Random suffix for Key Vault name (must be globally unique)
resource "random_string" "keyvault_suffix" {
  length  = 4
  special = false
  lower   = true
}

# ============================================================
# Current Azure Client for Terraform
# ============================================================
data "azurerm_client_config" "current" {}
