# Sentinel Analytics Rule (Whitelist-Aware) - Sample

Use this as a ready configuration when creating a **Scheduled query rule** in Microsoft Sentinel.

## Rule Metadata
- Name: `AVARS - Whitelist-Aware Firewall Threat Detection`
- Description: `Detect repeated suspicious firewall events while suppressing known-safe IPs from Sentinel watchlist ip_whitelist.`
- Severity: `High`
- Tactics: `InitialAccess`, `CredentialAccess`, `Discovery`
- Query Frequency: `5 minutes`
- Query Period: `30 minutes`
- Trigger Threshold: `0`
- Grouping: `SourceIP`
- Incident: `Enabled`

## Query (paste into Sentinel rule)
```kql
let SafeSourceIPs =
    _GetWatchlist('ip_whitelist')
    | project SafeIP = tostring(SearchKey);

AzureDiagnostics
| where ResourceType =~ "AZUREFIREWALLS"
| where TimeGenerated > ago(30m)
| extend SourceIP = tostring(split(msg_s, ":")[0])
| where isnotempty(SourceIP)
| where SourceIP !in (SafeSourceIPs)
| summarize AttemptCount = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by SourceIP
| where AttemptCount >= 5
| extend timestamp = LastSeen, IPCustomEntity = SourceIP
| order by AttemptCount desc
```

## Entity Mapping
- IP Address -> `IPCustomEntity`

## Automation Hook
- Attach Logic App: `incident_response_workflow.json`
- Keep HITL approval enabled for critical branch before firewall block.

## Notes
- Update `ip_whitelist` regularly and set expiry dates to avoid permanent bypasses.
- Start with `AttemptCount >= 5`; tune threshold to your lab baseline.
