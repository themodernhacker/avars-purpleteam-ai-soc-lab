param(
    [string]$ResourceGroupName,

    [string]$WorkspaceName,

    [switch]$Help,
    [string]$SubscriptionId,
    [string]$WatchlistAlias = "ip_whitelist",
    [string]$WatchlistDisplayName = "IP Whitelist",
    [string]$CsvPath = "scripts/kql/ip_whitelist_watchlist.csv",
    [string]$KqlPath = "scripts/kql/false_positive_whitelist.kql",
    [string]$RuleId = "avars-whitelist-aware-firewall-detection",
    [string]$RuleDisplayName = "AVARS - Whitelist-Aware Firewall Threat Detection",
    [string]$RuleSeverity = "High",
    [string]$QueryFrequency = "PT5M",
    [string]$QueryPeriod = "PT30M",
    [int]$TriggerThreshold = 0
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    $azCliPath = "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin"
    if (Test-Path $azCliPath) {
        $env:Path = "$azCliPath;$env:Path"
    }
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw "Azure CLI executable 'az' was not found. Install Azure CLI or add it to PATH."
}

function Invoke-AzCli {
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    $output = az @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ($output | Out-String)
    }

    return $output
}

if ($Help) {
    Write-Host "Usage:"
    Write-Host "  powershell -File scripts/kql/deploy_sentinel_whitelist_controls.ps1 -ResourceGroupName <rg> -WorkspaceName <workspace> [-SubscriptionId <subscription-id>]"
    Write-Host ""
    Write-Host "Optional parameters:"
    Write-Host "  -WatchlistAlias, -WatchlistDisplayName, -CsvPath, -KqlPath, -RuleId, -RuleDisplayName, -RuleSeverity, -QueryFrequency, -QueryPeriod, -TriggerThreshold"
    exit 0
}

if ([string]::IsNullOrWhiteSpace($ResourceGroupName) -or [string]::IsNullOrWhiteSpace($WorkspaceName)) {
    throw "ResourceGroupName and WorkspaceName are required. Use -Help for usage."
}

$account = (Invoke-AzCli account show --output json) | ConvertFrom-Json
if (-not $account) {
    throw "Azure CLI is not authenticated. Run: az login"
}

if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
    $SubscriptionId = $account.id
}

Invoke-AzCli account set --subscription $SubscriptionId | Out-Null

if (-not (Test-Path $CsvPath)) {
    throw "CSV file not found: $CsvPath"
}

if (-not (Test-Path $KqlPath)) {
    throw "KQL file not found: $KqlPath"
}

$provider = (Invoke-AzCli provider show --namespace Microsoft.SecurityInsights --output json) | ConvertFrom-Json

$watchlistsType = $provider.resourceTypes | Where-Object { $_.resourceType -eq "watchlists" } | Select-Object -First 1
$watchlistItemsType = $provider.resourceTypes | Where-Object { $_.resourceType -eq "watchlists/watchlistItems" } | Select-Object -First 1
$alertRulesType = $provider.resourceTypes | Where-Object { $_.resourceType -eq "alertRules" } | Select-Object -First 1

$watchlistApiVersion = if ($watchlistsType -and $watchlistsType.apiVersions -and $watchlistsType.apiVersions.Count -gt 0) { $watchlistsType.apiVersions[0] } else { $null }
$watchlistItemsApiVersion = if ($watchlistItemsType -and $watchlistItemsType.apiVersions -and $watchlistItemsType.apiVersions.Count -gt 0) { $watchlistItemsType.apiVersions[0] } else { $null }
$alertRulesApiVersion = if ($alertRulesType -and $alertRulesType.apiVersions -and $alertRulesType.apiVersions.Count -gt 0) { $alertRulesType.apiVersions[0] } else { $null }

$watchlistApiVersion = [string]$watchlistApiVersion
$watchlistItemsApiVersion = [string]$watchlistItemsApiVersion
$alertRulesApiVersion = [string]$alertRulesApiVersion

# Some tenants/provider metadata expose only "watchlists" and not child "watchlists/watchlistItems".
if ([string]::IsNullOrWhiteSpace($watchlistItemsApiVersion)) {
    $watchlistItemsApiVersion = $watchlistApiVersion
}

# Deterministic fallback for environments where provider metadata is incomplete.
if ([string]::IsNullOrWhiteSpace($watchlistApiVersion)) {
    $watchlistApiVersion = "2025-09-01"
}
if ([string]::IsNullOrWhiteSpace($watchlistItemsApiVersion)) {
    $watchlistItemsApiVersion = "2025-09-01"
}
if ([string]::IsNullOrWhiteSpace($alertRulesApiVersion)) {
    $alertRulesApiVersion = "2025-09-01"
}

$watchlistUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/watchlists/${WatchlistAlias}?api-version=$watchlistApiVersion"

$watchlistBody = @{
    properties = @{
        displayName = $WatchlistDisplayName
        provider = "Custom"
        source = "Local file"
        contentType = "text/csv"
        itemsSearchKey = "searchKey"
        description = "AVARS known-safe IP whitelist for false-positive suppression"
    }
} | ConvertTo-Json -Depth 10

$watchlistBodyFile = Join-Path $env:TEMP "avars-watchlist-body-$WatchlistAlias.json"
Set-Content -Path $watchlistBodyFile -Value $watchlistBody -Encoding UTF8

try {
    Invoke-AzCli rest --method put --uri $watchlistUri --body "@$watchlistBodyFile" --headers "Content-Type=application/json" --only-show-errors | Out-Null
}
catch {
    $err = $_.Exception.Message
    if ($err -match "SearchKey 'SearchKey' cannot be updated to 'searchKey'") {
        Write-Host "Existing watchlist uses immutable SearchKey casing. Recreating watchlist '$WatchlistAlias'..."
        Invoke-AzCli rest --method delete --uri $watchlistUri --only-show-errors | Out-Null
        Start-Sleep -Seconds 3
        Invoke-AzCli rest --method put --uri $watchlistUri --body "@$watchlistBodyFile" --headers "Content-Type=application/json" --only-show-errors | Out-Null
    }
    else {
        throw
    }
}

$rows = Import-Csv -Path $CsvPath
foreach ($row in $rows) {
    $itemId = [guid]::NewGuid().ToString()
    $itemUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/watchlists/${WatchlistAlias}/watchlistItems/${itemId}?api-version=$watchlistItemsApiVersion"

    $itemMap = @{}
    foreach ($p in $row.PSObject.Properties) {
        if ($p.Name -ieq "SearchKey" -or $p.Name -ieq "searchKey") {
            $itemMap["searchKey"] = [string]$p.Value
        }
        else {
            $itemMap[$p.Name] = [string]$p.Value
        }
    }

    if (-not $itemMap.ContainsKey("searchKey") -or [string]::IsNullOrWhiteSpace($itemMap["searchKey"])) {
        throw "CSV row is missing required SearchKey/searchKey value."
    }

    $itemBody = @{
        properties = @{
            itemsKeyValue = $itemMap
        }
    } | ConvertTo-Json -Depth 10

    $itemBodyFile = Join-Path $env:TEMP "avars-watchlist-item-$itemId.json"
    Set-Content -Path $itemBodyFile -Value $itemBody -Encoding UTF8

    Invoke-AzCli rest --method put --uri $itemUri --body "@$itemBodyFile" --headers "Content-Type=application/json" --only-show-errors | Out-Null
}

$query = Get-Content -Path $KqlPath -Raw

$alertRuleUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules/${RuleId}?api-version=$alertRulesApiVersion"
$alertRuleBody = @{
    kind = "Scheduled"
    properties = @{
        displayName         = $RuleDisplayName
        description         = "Detect repeated suspicious firewall activity while suppressing known-safe IPs from watchlist $WatchlistAlias."
        enabled             = $true
        query               = $query
        queryFrequency      = $QueryFrequency
        queryPeriod         = $QueryPeriod
        severity            = $RuleSeverity
        triggerOperator     = "GreaterThan"
        triggerThreshold    = $TriggerThreshold
        suppressionDuration = "PT1H"
        suppressionEnabled  = $false
        tactics             = @("InitialAccess", "CredentialAccess")
    }
} | ConvertTo-Json -Depth 20

$alertRuleBodyFile = Join-Path $env:TEMP "avars-alert-rule-$RuleId.json"
Set-Content -Path $alertRuleBodyFile -Value $alertRuleBody -Encoding UTF8

Invoke-AzCli rest --method put --uri $alertRuleUri --body "@$alertRuleBodyFile" --headers "Content-Type=application/json" --only-show-errors | Out-Null

Write-Host "Completed."
Write-Host "- Watchlist alias: $WatchlistAlias"
Write-Host "- Imported rows: $($rows.Count)"
Write-Host "- Scheduled rule ID: $RuleId"
