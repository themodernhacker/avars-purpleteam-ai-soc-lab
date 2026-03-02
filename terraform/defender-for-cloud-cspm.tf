# ==============================================================================
# Defender for Cloud / CSPM (Provider-Compatible Refactor)
# ==============================================================================

resource "azurerm_security_center_subscription_pricing" "defender_servers" {
  count         = var.enable_defender_cloud ? 1 : 0
  tier          = "Standard"
  resource_type = "VirtualMachines"
  subplan       = "P2"
}

resource "azurerm_security_center_subscription_pricing" "defender_storage" {
  count         = var.enable_defender_cloud ? 1 : 0
  tier          = "Standard"
  resource_type = "StorageAccounts"
  subplan       = "DefenderForStorageV2"
}

resource "azurerm_security_center_subscription_pricing" "defender_kubernetes" {
  count         = var.enable_defender_cloud ? 1 : 0
  tier          = "Standard"
  resource_type = "KubernetesService"
}

resource "azurerm_log_analytics_saved_search" "defender_recommendations" {
  count                      = var.enable_defender_cloud ? 1 : 0
  name                       = "DefenderCloudRecommendations"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.avars.id
  category                   = "Security"
  display_name               = "Defender for Cloud Recommendations"

  query = <<-KQL
    SecurityRecommendation
    | summarize RecommendationCount=count() by RecommendationName=tostring(RecommendationName), Severity=tostring(RecommendationSeverity)
    | order by RecommendationCount desc
  KQL

  function_alias = "GetDefenderRecommendations"
}

output "defender_cloud_enabled" {
  description = "Whether Defender for Cloud plans are enabled"
  value       = var.enable_defender_cloud
}
