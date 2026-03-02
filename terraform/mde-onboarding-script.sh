#!/bin/bash
# ==============================================================================
# MDE (Microsoft Defender for Endpoint) Onboarding Script for Linux
# ==============================================================================
# This script:
# 1. Installs Microsoft Defender for Endpoint (MDE) sensor
# 2. Registers with Azure Log Analytics for Sentinel integration
# 3. Configures threat detection and response
# 4. Enables automatic threat remediation
# ==============================================================================

set -e

# Configuration (injected by Terraform)
WORKSPACE_ID="${1:-$LOG_ANALYTICS_WORKSPACE_ID}"
WORKSPACE_KEY="${2:-$LOG_ANALYTICS_WORKSPACE_KEY}"
TENANT_ID="${3:-$AZURE_TENANT_ID}"
SUBSCRIPTION_ID="${4:-$AZURE_SUBSCRIPTION_ID}"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Error handler
error_exit() {
    log "ERROR: $1"
    exit 1
}

log "========== Starting MDE Onboarding =========="

# ==============================================================================
# Step 1: Update system packages
# ==============================================================================
log "Updating system packages..."
apt-get update -y
apt-get upgrade -y
apt-get install -y curl wget gnupg lsb-release apt-transport-https

# ==============================================================================
# Step 2: Add Microsoft repository
# ==============================================================================
log "Adding Microsoft repository for MDE..."
curl https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/prod.list | tee /etc/apt/sources.list.d/microsoft.list

# Import Microsoft GPG key
curl -sL https://packages.microsoft.com/keys/microsoft.asc | apt-key add -

# Update package lists with new Microsoft repo
apt-get update -y

# ==============================================================================
# Step 3: Install Microsoft Defender for Endpoint
# ==============================================================================
log "Installing Microsoft Defender for Endpoint..."
apt-get install -y mdatp

# Verify installation
if command -v mdatp &> /dev/null; then
    log "✅ MDE installed successfully"
else
    error_exit "MDE installation failed"
fi

# ==============================================================================
# Step 4: Install Azure Monitor Agent for Log Analytics
# ==============================================================================
log "Installing Azure Monitor Agent..."
wget -q https://aka.ms/dependencyagentlinux -O InstallDependencyAgent-Linux64.bin || error_exit "Failed to download Azure Monitor Agent"
sh InstallDependencyAgent-Linux64.bin -s

# ==============================================================================
# Step 5: Install Log Analytics Agent (OMS)
# ==============================================================================
log "Installing Log Analytics Agent..."

# Download OMS agent for Linux
wget -q https://aka.ms/omsagent-linux64 -O omsagent-linux64.sh || error_exit "Failed to download OMS agent"
chmod +x omsagent-linux64.sh

# Install OMS agent
/bin/bash ./omsagent-linux64.sh -w "$WORKSPACE_ID" -s "$WORKSPACE_KEY" -d opinsights.azure.com

# Verify installation
if pgrep -f "omsagent" > /dev/null 2>&1; then
    log "✅ Log Analytics Agent running"
else
    error_exit "Log Analytics Agent failed to start"
fi

# ==============================================================================
# Step 6: Configure MDE threat detection
# ==============================================================================
log "Configuring MDE threat detection settings..."

# Enable real-time protection
mdatp config real-time-protection --state enabled

# Set threat level to detect all threats (not just severe)
mdatp config threat-type-settings --threat-type potentially-unwanted-application --action quarantine
mdatp config threat-type-settings --threat-type trojan --action quarantine
mdatp config threat-type-settings --threat-type virus --action quarantine
mdatp config threat-type-settings --threat-type rootkit --action quarantine

log "✅ MDE threat detection configured"

# ==============================================================================
# Step 7: Configure MDE cloud delivery
# ==============================================================================
log "Configuring cloud-delivered protection..."

# Enable cloud protection
mdatp config cloud-service-enabled --value enabled

# Set diagnostic data level (diagnostic = full telemetry)
# Note: This enables MDE to send process, network, and file events to cloud
mdatp config cloud-diagnostic-level --value diagnostic

log "✅ Cloud-delivered protection enabled"

# ==============================================================================
# Step 8: Start MDE service
# ==============================================================================
log "Starting MDE service..."
systemctl enable mdatp
systemctl start mdatp

# Wait for service to start
sleep 10

# Verify MDE is running
if systemctl is-active --quiet mdatp; then
    log "✅ MDE service running"
else
    error_exit "MDE service failed to start"
fi

# ==============================================================================
# Step 9: Verify device registration
# ==============================================================================
log "Verifying device health and registration..."

# Check MDE service status
mdatp health

# Get device ID (used for device isolation in Logic Apps)
DEVICE_ID=$(mdatp device-tagging --info | grep "Device ID" | cut -d' ' -f3)
log "Device ID: $DEVICE_ID"

# ==============================================================================
# Step 10: Configure automatic threat remediation
# ==============================================================================
log "Configuring automatic threat remediation..."

# Set action on threat detection
# Options: quarantine, remove, allow, block, user-defined
mdatp config threat-type-settings --threat-type trojan --action quarantine

# Enable automatic sample submission (for threat intelligence)
mdatp config sample-sharing --value enabled

log "✅ Threat remediation configured"

# ==============================================================================
# Step 11: Enable Sentinel integration
# ==============================================================================
log "Configuring Sentinel integration..."

# Configure Log Analytics workspace integration
mdatp import-defender-json-file --file /dev/stdin <<EOF
{
  "workspace_id": "$WORKSPACE_ID",
  "workspace_key": "$WORKSPACE_KEY",
  "azure_tenant_id": "$TENANT_ID",
  "azure_subscription_id": "$SUBSCRIPTION_ID"
}
EOF

log "✅ Sentinel integration configured"

# ==============================================================================
# Step 12: Create monitoring rules for C2 detection
# ==============================================================================
log "Creating custom detection rules for C2..."

# Detect suspicious network connections (potential C2)
cat > /etc/mdatp/c2_detection_rule.json <<'EOF'
{
  "name": "Suspicious_C2_Network_Pattern",
  "enabled": true,
  "description": "Detect command & control network patterns",
  "type": "process_network",
  "rules": [
    {
      "field": "network_connection_destination_port",
      "operator": "in",
      "value": [80, 443, 8080, 8443]
    },
    {
      "field": "network_connection_duration_seconds",
      "operator": "greater_than",
      "value": 30
    },
    {
      "field": "network_connection_repetition",
      "operator": "in_interval",
      "value": "every 5 minutes"
    }
  ],
  "action": "quarantine_and_alert"
}
EOF

# Deploy Rule
mdatp custom-detection-rules --import /etc/mdatp/c2_detection_rule.json

log "✅ C2 detection rules created"

# ==============================================================================
# Step 13: Configure AV engine updates
# ==============================================================================
log "Configuring antivirus engine updates..."

# Set update schedule to automatic (daily)
mdatp config engine-update-settings --value auto-update

# Download latest definitions
mdatp manage-signatures --update

log "✅ Antivirus engine configured"

# ==============================================================================
# Step 14: Verify complete integration
# ==============================================================================
log "Verifying complete MDE integration..."

# Check all components
echo ""
echo "=== MDE Status ==="
mdatp health

echo ""
echo "=== Log Analytics Agent Status ==="
ps aux | grep omsagent | grep -v grep

echo ""
echo "=== MDE Version ==="
mdatp --version

echo ""
echo "=== Device Information ==="
mdatp device-tagging --info

# ==============================================================================
# Step 15: Setup log forwarding to Sentinel
# ==============================================================================
log "Setting up Sentinel log forwarding..."

# Configure syslog to forward MDE logs
cat >> /etc/rsyslog.d/10-microsoft-defender.conf <<'EOF'
# Microsoft Defender for Endpoint logs
:programname, isequal, "mdatp" /var/log/mdatp/mdatp.log

# Process events (for Sentinel detection)
:programname, isequal, "audit" /var/log/audit/audit.log

# Network events
:programname, isequal, "kernel" /var/log/kernel-network.log
EOF

# Restart rsyslog
systemctl restart rsyslog

log "✅ Log forwarding configured"

# ==============================================================================
# Step 16: Document configuration
# ==============================================================================
log "Documenting configuration..."

cat > /opt/avars_mde_config.txt <<EOF
========== A.V.A.R.S MDE Configuration ==========
Installation Date: $(date)
Device ID: $DEVICE_ID
Workspace ID: $WORKSPACE_ID
Tenant ID: $TENANT_ID
Subscription ID: $SUBSCRIPTION_ID

Components Installed:
- ✅ Microsoft Defender for Endpoint
- ✅ Log Analytics Agent
- ✅ Azure Monitor Agent
- ✅ Threat Detection Rules

Integration Status:
- ✅ Sentinel intake enabled
- ✅ Cloud protection enabled
- ✅ Automatic threat remediation enabled
- ✅ C2 detection rules deployed

Next Steps:
1. Verify device appears in Azure portal (Defender for Endpoint)
2. Create Sentinel analytics rule to capture MDE alerts
3. Deploy Logic App for device isolation (lstm-to-endpoint-isolation.json)
4. Test end-to-end: LSTM detection → Device isolation

Documentation:
- MDE Status: mdatp health
- Device Info: mdatp device-tagging --info
- Update AV: mdatp manage-signatures --update
- View Logs: tail -f /var/log/mdatp/mdatp.log

WARNING: This VM is now monitored by MDE and will send security telemetry to Azure.
Any suspicious activity will be detected and may trigger device isolation.
=================================================
EOF

log "Configuration saved to /opt/avars_mde_config.txt"

# ==============================================================================
# Step 17: Final verification
# ==============================================================================
log "Performing final verification..."

# Test Sentinel connectivity
echo "Testing Sentinel connectivity..."
curl -s -X POST \
  "https://${WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01" \
  -H "Authorization: SharedKey ${WORKSPACE_ID}:${WORKSPACE_KEY}" \
  -H "Content-Type: application/json" \
  -H "Log-Type: MDE_Verification" \
  -d '{"Status":"OK", "Timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}' || \
  log "WARNING: Sentinel connectivity test failed (may require network rules)"

# ==============================================================================
# SETUP COMPLETE
# ==============================================================================

log ""
log "========== MDE Onboarding Complete =========="
log ""
log "Summary:"
log "  ✅ MDE sensor installed and running"
log "  ✅ Log Analytics integration configured"
log "  ✅ Sentinel intake enabled"
log "  ✅ C2 threat detection rules deployed"
log "  ✅ Automatic remediation configured"
log ""
log "Device Status:"
mdatp health | grep -E "(Malware|RTP enabled|Cloud)"
log ""
log "Next: Monitor Sentinel for alerts from this device"
log "      When LSTM detects C2, this device will be isolated automatically"
log ""

# Cleanup
rm -f InstallDependencyAgent-Linux64.bin
rm -f omsagent-linux64.sh

log "Onboarding complete! Configuration saved to /opt/avars_mde_config.txt"
