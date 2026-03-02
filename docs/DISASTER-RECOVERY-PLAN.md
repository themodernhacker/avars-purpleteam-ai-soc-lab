# Disaster Recovery Plan — Project A.V.A.R.S

## Purpose
This Disaster Recovery (DR) plan documents how to achieve geo-redundancy and failover for critical A.V.A.R.S components so the SOC can continue operating if a primary region becomes unavailable.

## Objectives
- **RTO (Recovery Time Objective):** Target 5–15 minutes for critical services (traffic failover + Sentinel ingestion)
- **RPO (Recovery Point Objective):** Target <5 minutes for telemetry and logs (where possible)
- **Scope:** Sentinel workspace, Log Analytics, core VMs (Sentinel connectors), storage accounts, SQL databases, Logic Apps orchestration, and vulnerability scanning endpoints.

## Strategy Overview
- Use an **Active-Passive** model: primary region (e.g., UK South / Sheffield) with a standby secondary region (e.g., UK West / London).
- Use **Azure Traffic Manager** or Front Door for DNS-based failover to route user/API traffic to the healthy region.
- Use **SQL Database Active Geo-Replication** for database failover.
- Use **RA-GRS** (Read-Access Geo-Redundant Storage) or GRS for blob storage.
- Use **Azure Site Recovery (ASR)** to replicate VMs if full VM parity is required.
- Deploy a secondary Sentinel workspace and link data connectors to the standby region; implement playbooks in both regions.

## High-Level Architecture
```
User / Sensor -> Traffic Manager -> Primary Region (Sentinel) -> Logic Apps
                               \-> Secondary Region (standby)
```

## Terraform Implementation Notes (example snippets)

- Use a variable `enable_dr = true` and `dr_region = "UK West"` to conditionally deploy DR resources.

### Traffic Manager (failover profile) — example snippet
```hcl
resource "azurerm_traffic_manager_profile" "tm_failover" {
  name                = "${local.resource_prefix}-tm"
  resource_group_name = azurerm_resource_group.rg.name
  profile_status      = "Enabled"
  traffic_routing_method = "Priority"

  dns_config {
    relative_name = "${local.resource_prefix}-tm"
    ttl           = 30
  }

  monitor_config {
    protocol = "HTTPS"
    port     = 443
    path     = "/healthz"
  }
}

resource "azurerm_traffic_manager_endpoints" "primary" {
  name                   = "primary-endpoint"
  profile_name           = azurerm_traffic_manager_profile.tm_failover.name
  resource_group_name    = azurerm_resource_group.rg.name
  target_resource_id     = azurerm_public_ip.primary_service_pip.id
  endpoint_status        = "Enabled"
  priority               = 1
}

resource "azurerm_traffic_manager_endpoints" "secondary" {
  name                   = "secondary-endpoint"
  profile_name           = azurerm_traffic_manager_profile.tm_failover.name
  resource_group_name    = azurerm_resource_group.rg.name
  target_resource_id     = azurerm_public_ip.secondary_service_pip.id
  endpoint_status        = "Enabled"
  priority               = 2
}
```

### SQL Database Geo-Replication — example snippet
```hcl
resource "azurerm_sql_database" "primary_db" {
  name                = "avars-sql-db"
  resource_group_name = azurerm_resource_group.rg.name
  location            = var.location
  server_name         = azurerm_mssql_server.primary.name
  sku_name            = "S0"
}

resource "azurerm_sql_database_replica" "geo_replica" {
  name                = "avars-sql-db-replica"
  resource_group_name = azurerm_resource_group.rg.name
  location            = var.dr_region
  server_name         = azurerm_mssql_server.secondary.name
  create_mode         = "OnlineSecondary"
  source_database_id  = azurerm_sql_database.primary_db.id
}
```

### Storage Account — enable RA-GRS
```hcl
resource "azurerm_storage_account" "vuln_scans" {
  name                     = "${replace(local.resource_prefix, "-", "")}vulnscan"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "RAGRS"
}
```

## Failover Procedures
1. **Detection:** Monitor health probes and Sentinel alerts; if primary region fails, Traffic Manager will route to secondary after health checks fail.
2. **Automatic DNS failover:** Traffic Manager (priority) promotes secondary when primary is unhealthy.
3. **Confirm Sentinel ingestion:** Ensure Beat/Agent endpoints in the standby region are enabled and connectors are active.
4. **Promote DB replica:** For SQL, perform a failover to the secondary replica (manual or scriptable).
5. **Activate playbooks:** Ensure Logic Apps in DR region are enabled to run on incoming incidents.
6. **Post-mortem:** After recovery, investigate root cause and revert traffic when primary is healthy.

## Testing & Validation
- Regular DR drills: run quarterly failover tests.
- Validate RTO/RPO during drills and document gaps.
- Test telemetry continuity and alerting during failover.

## Limitations & Considerations
- Sentinel workspace data retention and cross-region replication have costs and limitations.
- Some Azure services are region-specific; full parity may require duplicate provisioning and licensing.
- DNS-based failover has TTL behavior—expect short delay (seconds to minutes).

## Appendix: Runbook Snippets
- Promote SQL replica (Azure CLI):
```bash
az sql db replica set-primary --resource-group <rg> --server <secondary-server> --name avars-sql-db
```

- Trigger Traffic Manager re-evaluation:
```bash
az network traffic-manager profile update --resource-group <rg> --name <tm-name> --set profileStatus=Enabled
```

---
*Prepared for Project A.V.A.R.S — Cloud Security Engineer*