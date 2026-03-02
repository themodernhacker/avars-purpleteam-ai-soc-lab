# Monitoring and SIEM Configuration (Provider-Compatible)

# ============================================================
# 1. ACTION GROUP FOR ALERT NOTIFICATIONS
# ============================================================
resource "azurerm_monitor_action_group" "avars" {
  name                = "${local.resource_prefix}-action-group"
  resource_group_name = azurerm_resource_group.avars.name
  short_name          = "AVARS"
  tags                = local.common_tags
}

# ============================================================
# 2. SENTINEL SCHEDULED DETECTION RULES (KQL + MITRE aligned)
# ============================================================
resource "azurerm_sentinel_alert_rule_scheduled" "sql_injection_detection" {
  count                      = var.deploy_sentinel_rules ? 1 : 0
  name                       = "SQL-Injection-Attack-Detection"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.avars.id
  display_name               = "SQL Injection Attack Detected"
  severity                   = "High"
  enabled                    = true
  query_frequency            = "PT5M"
  query_period               = "PT30M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0

  query = <<-KQL
    let suspiciousSQLPatterns = dynamic([
      "union", "select", "drop", "insert", "update", "delete", "exec", "xp_"
    ]);
    AzureDiagnostics
    | where Category == "AzureFirewallApplicationRule"
    | where isnotempty(msg_s)
    | where msg_s has_any (suspiciousSQLPatterns)
    | parse msg_s with * "request from " SourceIP ":" *
    | where isnotempty(SourceIP)
    | project TimeGenerated, SourceIP, msg_s
  KQL

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "SourceIP"
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

resource "azurerm_sentinel_alert_rule_scheduled" "credential_stuffing_detection" {
  count                      = var.deploy_sentinel_rules ? 1 : 0
  name                       = "Credential-Stuffing-Attack-Detection"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.avars.id
  display_name               = "Credential Stuffing Attack Detected"
  severity                   = "High"
  enabled                    = true
  query_frequency            = "PT5M"
  query_period               = "PT30M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0

  query = <<-KQL
    let FailedLoginThreshold = 10;
    AzureDiagnostics
    | where Category == "AzureFirewallApplicationRule"
    | where isnotempty(msg_s)
    | where msg_s contains "401" or msg_s contains "403"
    | parse msg_s with * "request from " SourceIP ":" *
    | where isnotempty(SourceIP)
    | summarize FailedAttempts = count() by SourceIP, bin(TimeGenerated, 5m)
    | where FailedAttempts > FailedLoginThreshold
    | project TimeGenerated, SourceIP, FailedAttempts
  KQL

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "SourceIP"
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

resource "azurerm_sentinel_alert_rule_scheduled" "port_scanning_detection" {
  count                      = var.deploy_sentinel_rules ? 1 : 0
  name                       = "Port-Scanning-Behavior-Detection"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.avars.id
  display_name               = "Port Scanning Detected"
  severity                   = "Medium"
  enabled                    = true
  query_frequency            = "PT5M"
  query_period               = "PT30M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0

  query = <<-KQL
    let PortScanThreshold = 50;
    AzureDiagnostics
    | where Category == "AzureFirewallApplicationRule"
    | where isnotempty(msg_s)
    | where msg_s contains "DENY"
    | parse msg_s with * "request from " SourceIP ":" *
    | where isnotempty(SourceIP)
    | summarize Attempts = count() by SourceIP, bin(TimeGenerated, 5m)
    | where Attempts > PortScanThreshold
    | project TimeGenerated, SourceIP, Attempts
  KQL

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "SourceIP"
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

resource "azurerm_sentinel_alert_rule_scheduled" "anomalous_authentication" {
  count                      = var.deploy_sentinel_rules ? 1 : 0
  name                       = "Anomalous-Authentication-Patterns"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.avars.id
  display_name               = "Anomalous Authentication Patterns Detected"
  severity                   = "Medium"
  enabled                    = true
  query_frequency            = "PT15M"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0

  query = <<-KQL
    let failureThreshold = 5;
    AzureDiagnostics
    | where Category == "AzureFirewallApplicationRule"
    | where isnotempty(msg_s)
    | where msg_s contains "401" or msg_s contains "403"
    | parse msg_s with * "request from " SourceIP ":" *
    | where isnotempty(SourceIP)
    | summarize FailureCount = count() by SourceIP, bin(TimeGenerated, 10m)
    | where FailureCount >= failureThreshold
    | project TimeGenerated, SourceIP, FailureCount, Technique="T1110"
  KQL

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "SourceIP"
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

# ============================================================
# 3. AZURE MONITOR METRIC ALERTS
# ============================================================
resource "azurerm_monitor_metric_alert" "firewall_threat_intelligence" {
  count               = var.deploy_metric_alerts ? 1 : 0
  name                = "${local.resource_prefix}-firewall-threat-intel"
  resource_group_name = azurerm_resource_group.avars.name
  scopes              = [azurerm_firewall.avars.id]
  description         = "Alert when firewall health drops below threshold"
  enabled             = true
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT5M"

  criteria {
    metric_name            = "Throughput"
    metric_namespace       = "Microsoft.Network/azureFirewalls"
    aggregation            = "Average"
    operator               = "GreaterThan"
    threshold              = 1
    skip_metric_validation = true
  }

  action {
    action_group_id = azurerm_monitor_action_group.avars.id
  }
}

# ============================================================
# 4. LOG ANALYTICS SOLUTIONS
# ============================================================
resource "azurerm_log_analytics_solution" "change_tracking" {
  solution_name         = "ChangeTracking"
  location              = azurerm_resource_group.avars.location
  resource_group_name   = azurerm_resource_group.avars.name
  workspace_name        = azurerm_log_analytics_workspace.avars.name
  workspace_resource_id = azurerm_log_analytics_workspace.avars.id

  plan {
    publisher = "Microsoft"
    product   = "OMSGallery/ChangeTracking"
  }
}

resource "azurerm_log_analytics_solution" "security_audit" {
  solution_name         = "SecurityCenterFree"
  location              = azurerm_resource_group.avars.location
  resource_group_name   = azurerm_resource_group.avars.name
  workspace_name        = azurerm_log_analytics_workspace.avars.name
  workspace_resource_id = azurerm_log_analytics_workspace.avars.id

  plan {
    publisher = "Microsoft"
    product   = "OMSGallery/SecurityCenterFree"
  }
}
