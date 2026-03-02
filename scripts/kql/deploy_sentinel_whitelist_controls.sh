#!/usr/bin/env bash
set -euo pipefail

RESOURCE_GROUP_NAME=""
WORKSPACE_NAME=""
SUBSCRIPTION_ID=""
WATCHLIST_ALIAS="ip_whitelist"
WATCHLIST_DISPLAY_NAME="IP Whitelist"
CSV_PATH="scripts/kql/ip_whitelist_watchlist.csv"
KQL_PATH="scripts/kql/false_positive_whitelist.kql"
RULE_ID="avars-whitelist-aware-firewall-detection"
RULE_DISPLAY_NAME="AVARS - Whitelist-Aware Firewall Threat Detection"
RULE_SEVERITY="High"
QUERY_FREQUENCY="PT5M"
QUERY_PERIOD="PT30M"
TRIGGER_THRESHOLD="0"

usage() {
  cat <<'USAGE'
Usage:
  bash scripts/kql/deploy_sentinel_whitelist_controls.sh \
    --resource-group <rg> \
    --workspace-name <workspace> \
    [--subscription-id <subscription-id>] \
    [--watchlist-alias ip_whitelist] \
    [--csv-path scripts/kql/ip_whitelist_watchlist.csv] \
    [--kql-path scripts/kql/false_positive_whitelist.kql]
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --resource-group|-g)
      RESOURCE_GROUP_NAME="$2"
      shift 2
      ;;
    --workspace-name|-w)
      WORKSPACE_NAME="$2"
      shift 2
      ;;
    --subscription-id|-s)
      SUBSCRIPTION_ID="$2"
      shift 2
      ;;
    --watchlist-alias)
      WATCHLIST_ALIAS="$2"
      shift 2
      ;;
    --watchlist-display-name)
      WATCHLIST_DISPLAY_NAME="$2"
      shift 2
      ;;
    --csv-path)
      CSV_PATH="$2"
      shift 2
      ;;
    --kql-path)
      KQL_PATH="$2"
      shift 2
      ;;
    --rule-id)
      RULE_ID="$2"
      shift 2
      ;;
    --rule-display-name)
      RULE_DISPLAY_NAME="$2"
      shift 2
      ;;
    --rule-severity)
      RULE_SEVERITY="$2"
      shift 2
      ;;
    --query-frequency)
      QUERY_FREQUENCY="$2"
      shift 2
      ;;
    --query-period)
      QUERY_PERIOD="$2"
      shift 2
      ;;
    --trigger-threshold)
      TRIGGER_THRESHOLD="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$RESOURCE_GROUP_NAME" || -z "$WORKSPACE_NAME" ]]; then
  echo "Error: --resource-group and --workspace-name are required." >&2
  usage
  exit 1
fi

if ! command -v az >/dev/null 2>&1; then
  echo "Error: Azure CLI (az) is not installed or not on PATH." >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 is required for CSV parsing." >&2
  exit 1
fi

if [[ ! -f "$CSV_PATH" ]]; then
  echo "Error: CSV file not found: $CSV_PATH" >&2
  exit 1
fi

if [[ ! -f "$KQL_PATH" ]]; then
  echo "Error: KQL file not found: $KQL_PATH" >&2
  exit 1
fi

az account show >/dev/null 2>&1 || {
  echo "Error: Azure CLI is not authenticated. Run: az login" >&2
  exit 1
}

if [[ -z "$SUBSCRIPTION_ID" ]]; then
  SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
fi

az account set --subscription "$SUBSCRIPTION_ID" >/dev/null
az extension add --name sentinel --only-show-errors >/dev/null

WATCHLIST_API_VERSION="$(az provider show --namespace Microsoft.SecurityInsights --query "resourceTypes[?resourceType=='watchlists'].apiVersions[0]" -o tsv)"
WATCHLIST_ITEMS_API_VERSION="$(az provider show --namespace Microsoft.SecurityInsights --query "resourceTypes[?resourceType=='watchlists/watchlistItems'].apiVersions[0]" -o tsv)"

if [[ -z "$WATCHLIST_API_VERSION" || -z "$WATCHLIST_ITEMS_API_VERSION" ]]; then
  echo "Error: Unable to resolve Microsoft.SecurityInsights watchlist API versions." >&2
  exit 1
fi

WATCHLIST_URI="https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP_NAME}/providers/Microsoft.OperationalInsights/workspaces/${WORKSPACE_NAME}/providers/Microsoft.SecurityInsights/watchlists/${WATCHLIST_ALIAS}?api-version=${WATCHLIST_API_VERSION}"

WATCHLIST_BODY="$(cat <<JSON
{
  "properties": {
    "displayName": "${WATCHLIST_DISPLAY_NAME}",
    "provider": "Custom",
    "source": "Local file",
    "contentType": "text/csv",
    "itemsSearchKey": "SearchKey",
    "description": "AVARS known-safe IP whitelist for false-positive suppression"
  }
}
JSON
)"

az rest --method put --uri "$WATCHLIST_URI" --body "$WATCHLIST_BODY" --headers "Content-Type=application/json" --only-show-errors >/dev/null

IMPORTED_ROWS=0
while IFS=$'\t' read -r ITEM_ID ITEM_BODY; do
  [[ -z "${ITEM_ID}" ]] && continue

  ITEM_URI="https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP_NAME}/providers/Microsoft.OperationalInsights/workspaces/${WORKSPACE_NAME}/providers/Microsoft.SecurityInsights/watchlists/${WATCHLIST_ALIAS}/watchlistItems/${ITEM_ID}?api-version=${WATCHLIST_ITEMS_API_VERSION}"

  az rest --method put --uri "$ITEM_URI" --body "$ITEM_BODY" --headers "Content-Type=application/json" --only-show-errors >/dev/null
  IMPORTED_ROWS=$((IMPORTED_ROWS + 1))
done < <(
  python3 - "$CSV_PATH" <<'PY'
import csv
import json
import sys
import uuid

csv_path = sys.argv[1]
with open(csv_path, newline='', encoding='utf-8-sig') as f:
    reader = csv.DictReader(f)
    for row in reader:
        item_id = str(uuid.uuid4())
        item_body = json.dumps({"properties": {"itemsKeyValue": {k: str(v) for k, v in row.items()}}}, separators=(",", ":"))
        print(f"{item_id}\t{item_body}")
PY
)

QUERY_COMPACT="$(tr '\n' ' ' < "$KQL_PATH")"

az sentinel alert-rule create \
  --resource-group "$RESOURCE_GROUP_NAME" \
  --workspace-name "$WORKSPACE_NAME" \
  --rule-id "$RULE_ID" \
  --scheduled-alert-rule \
    "query=$QUERY_COMPACT" \
    "query-frequency=$QUERY_FREQUENCY" \
    "query-period=$QUERY_PERIOD" \
    "severity=$RULE_SEVERITY" \
    "trigger-operator=GreaterThan" \
    "trigger-threshold=$TRIGGER_THRESHOLD" \
    "description=Detect repeated suspicious firewall activity while suppressing known-safe IPs from watchlist $WATCHLIST_ALIAS." \
    "display-name=$RULE_DISPLAY_NAME" \
    "enabled=true" \
    "suppression-duration=PT1H" \
    "suppression-enabled=false" \
    "tactics=InitialAccess" \
    "tactics=CredentialAccess" \
    "kind=Scheduled" \
  --only-show-errors >/dev/null

echo "Completed."
echo "- Watchlist alias: ${WATCHLIST_ALIAS}"
echo "- Imported rows: ${IMPORTED_ROWS}"
echo "- Scheduled rule ID: ${RULE_ID}"
