# ==============================================================================
# Defender for Endpoint Integration (Provider-Compatible Refactor)
# ==============================================================================

variable "enable_defender_endpoint" {
  description = "Enable Defender for Endpoint workflow resources"
  type        = bool
  default     = true
}

resource "azurerm_monitor_action_group" "mde_response_actions" {
  count               = var.enable_defender_endpoint ? 1 : 0
  name                = "${local.resource_prefix}-mde-action-group"
  resource_group_name = azurerm_resource_group.avars.name
  short_name          = "MDEACT"
  tags = merge(local.common_tags, {
    Module = "defender-endpoint"
    Scope  = "response"
  })
}

resource "azurerm_sentinel_alert_rule_scheduled" "mde_isolation_trigger" {
  count                      = var.enable_defender_endpoint ? 1 : 0
  name                       = "MDE-Suspicious-Endpoint-Trigger"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.avars.id
  display_name               = "Suspicious Endpoint Activity (MDE)"
  severity                   = "High"
  enabled                    = true
  query_frequency            = "PT5M"
  query_period               = "PT30M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0

  query = <<-KQL
    SecurityAlert
    | where ProductName has "Microsoft Defender for Endpoint"
    | where AlertSeverity in ("High", "Medium")
    | project TimeGenerated, AlertName, AlertSeverity, CompromisedEntity
  KQL

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "CompromisedEntity"
    }
  }

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = true
      reopen_closed_incidents = false
      lookback_duration       = "PT5H"
    }
  }

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.avars]
}

output "defender_endpoint_rule_name" {
  description = "Sentinel rule used as Defender Endpoint response trigger"
  value       = var.enable_defender_endpoint ? azurerm_sentinel_alert_rule_scheduled.mde_isolation_trigger[0].name : null
}
