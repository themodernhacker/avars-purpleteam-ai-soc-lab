# Project A.V.A.R.S - Complete Deployment Guide

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Phase 1: Infrastructure Deployment](#phase-1-infrastructure-deployment)
3. [Phase 2: Attack Simulation](#phase-2-attack-simulation)
4. [Phase 3: AI/ML Integration](#phase-3-aiml-integration)
5. [Phase 4: Automated Response](#phase-4-automated-response)
6. [Troubleshooting](#troubleshooting)
7. [Cost Estimation](#cost-estimation)

---

## Prerequisites

> Note: The `terraform/` root is the validated deployment path with all modules reintegrated.
> Open-source safety note: keep `terraform.tfvars` local only; never commit it with real IDs.

### Required Tools
- Terraform >= 1.5.0
- Azure CLI 2.50+
- Python 3.9+
- Git
- Visual Studio Code (recommended)

### Azure Subscription Requirements
- Minimum: Pay-As-You-Go subscription
- Quota for: VMs, Container Instances, Log Analytics, Firewall
- Service Principal with Contributor role
- If using Azure for Students, expect stricter VM/ACI quotas and occasional SKU unavailability in `eastus`

### Estimated Prerequisites Time
- **Account Setup**: 15 minutes
- **Tool Installation**: 20 minutes
- **Service Principal Creation**: 10 minutes

---

## Phase 1: Infrastructure Deployment

### 1.1 Pre-Deployment Setup

```bash
# Clone the project
git clone https://github.com/your-repo/avars.git
cd avars

# Login to Azure
az login
az account set --subscription "YOUR_SUBSCRIPTION_ID"

# Create service principal for Terraform
az ad sp create-for-rbac --name "avars-terraform" \
  --role "Contributor" \
  --scopes /subscriptions/YOUR_SUBSCRIPTION_ID

# Export service principal credentials
export ARM_SUBSCRIPTION_ID="YOUR_SUBSCRIPTION_ID"
export ARM_CLIENT_ID="YOUR_CLIENT_ID"
export ARM_CLIENT_SECRET="YOUR_CLIENT_SECRET"
export ARM_TENANT_ID="YOUR_TENANT_ID"
```

### 1.2 Configure Terraform Variables

```bash
cd terraform

# Copy example variables
cp terraform.tfvars.example terraform.tfvars

# Edit with your values
nano terraform.tfvars
```

**Key variables to update:**
```hcl
azure_subscription_id = "your-subscription-id"
azure_tenant_id       = "your-tenant-id"
location              = "eastus"  # or your preferred region
resource_group_name   = "avars-rg"
```

If `eastus` has capacity issues, change `location` to another supported region (for example `centralus`) and redeploy.

**Cost Optimization Tips:**
- Use `Standard_B2s` for Kali VM (cheaper than higher tiers)
- Set `log_analytics_retention_days = 7` for lab environment
- Use `Standard` Firewall SKU

### 1.3 Deploy Infrastructure

```bash
# Initialize Terraform
terraform init

# Plan deployment
terraform plan -out=tfplan

# Review the plan (should show ~40+ resources)
# Expected resources:
# - 3 Virtual Networks
# - Azure Firewall + Public IP
# - 2 Honeypot Containers
# - 1 Kali Linux VM
# - Log Analytics Workspace
# - Sentinel instance

# Apply configuration
terraform apply tfplan
```

**Expected Deployment Time**: 20-30 minutes

### 1.4 Capture Outputs

```bash
# Save outputs for next phases
terraform output -json > outputs.json

# Extract critical values
FIREWALL_IP=$(terraform output -raw firewall_public_ip)
JUICE_SHOP_URL=$(terraform output -raw owasp_juice_shop_url)
SSH_HONEYPOT=$(terraform output -raw ssh_honeypot_url)
KALI_IP=$(terraform output -raw kali_vm_public_ip)
WORKSPACE_ID=$(terraform output -raw log_analytics_workspace_id)

echo "Critical Infrastructure:"
echo "========================"
echo "Firewall Public IP: $FIREWALL_IP"
echo "Juice Shop (Honeypot): $JUICE_SHOP_URL"
echo "SSH Honeypot: $SSH_HONEYPOT"
echo "Kali Linux VM: $KALI_IP"
echo "Log Analytics: $WORKSPACE_ID"
```

**Post-Deployment Validation**

```bash
# Check all resources created
az resource list -o table --query "[?resourceGroup=='avars-rg'].{Name:name, Type:type, Status:managedBy}"

# Verify Sentinel is enabled
az sentinel workspace list -g avars-rg

# Test connectivity to honeypots
curl -s http://$JUICE_SHOP_URL | grep -i "juice" && echo "✓ Juice Shop Running"
ssh-keyscan $SSH_HONEYPOT 2>/dev/null | grep -q "SSH" && echo "✓ SSH Honeypot Running"
```

---

## Phase 2: Attack Simulation

### 2.1 Connect to Kali Linux VM

```bash
# Get Kali passwords from Key Vault
az keyvault secret show \
  --vault-name avars-lab-kv-XXXX \
  --name kali-vm-password \
  --query value -o tsv

# SSH into Kali VM
ssh azureuser@$KALI_IP

# Update packages (first time)
sudo apt-get update && sudo apt-get upgrade -y
```

### 2.2 Run Credential Stuffing Attack

```bash
# From your local machine (not Kali)

# Copy attack script to project
python scripts/attacks/credential_stuffing.py http://<JUICE_SHOP_URL> \
  --delay 0.3 \
  --max-attempts 25

# Review logs
cat credential_stuffing_*.log

# Expected output:
# - Successful logins may vary (depends on Juice Shop configuration)
# - Failed attempts: 20-25
# - Attack duration: 10-15 seconds
```

### 2.3 Run SQL Injection Attack

```bash
# SQL injection against Juice Shop
python scripts/attacks/sql_injection.py http://<JUICE_SHOP_URL> \
  --delay 0.5 \
  --timeout 10

# This will:
# - Test 6 payload categories
# - 5 endpoints per category
# - 5 parameters per endpoint
# Total: ~150 injection attempts
```

### 2.4 Monitor Attack in Sentinel

```bash
# In Azure Portal:
# 1. Navigate to Microsoft Sentinel
# 2. Go to "Logs" section
# 3. Run KQL queries from scripts/kql/mitre_mapping.kql

# Example query to see live attacks:
# Run in Sentinel Logs:
AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where TimeGenerated > ago(30m)
| summarize count() by SourceIP, DestinationIP, msg_s
```

**Expected Detections**:
- ✓ 401/403 responses from Juice Shop (auth failures)
- ✓ Suspicious query patterns
- ✓ Multiple failed login attempts from single IP
- ✓ SQL injection patterns in URLs

### 2.5 Configure False-Positive Watchlist (Sentinel)

In Sentinel, create a watchlist named `ip_whitelist` with a `SearchKey` column containing known-safe source IPs (for example office NAT or VPN egress IPs).

You can import the provided template directly:

```bash
# File path in this repo:
# scripts/kql/ip_whitelist_watchlist.csv
```

Then use `scripts/kql/false_positive_whitelist.kql` in analytics rules so known-safe entities are excluded from alert generation.

For a ready rule configuration (name, severity, cadence, and query), use:
- `scripts/kql/false_positive_whitelist_analytics_rule.md`

CLI-only automation (no portal clicks):

```powershell
pwsh -File scripts/kql/deploy_sentinel_whitelist_controls.ps1 -ResourceGroupName avars-rg -WorkspaceName avars-law -SubscriptionId <subscription-id>
```

```bash
bash scripts/kql/deploy_sentinel_whitelist_controls.sh --resource-group avars-rg --workspace-name avars-law --subscription-id <subscription-id>
```

This command set will:
- Create/update watchlist alias `ip_whitelist`
- Import rows from `scripts/kql/ip_whitelist_watchlist.csv`
- Create/update scheduled analytics rule using `scripts/kql/false_positive_whitelist.kql`

---

## Phase 3: AI/ML Integration

### 3.1 Deploy Anomaly Detection Model

```bash
# Navigate to ML notebooks directory
cd ml-notebooks

# Open and run the anomaly detection notebook
# In Azure ML Studio or Jupyter:
jupyter notebook anomaly_detection.ipynb

# Run all cells
# This will:
# 1. Fetch 24 hours of firewall logs
# 2. Engineer features
# 3. Train Isolation Forest
# 4. Train Random Forest
# 5. Save models to ./models/ directory
```

**Expected Output**:
- Isolation Forest: Detects ~15% of traffic as anomalous
- Random Forest: ROC-AUC >= 0.92
- Feature importance: bytes_sent, destination_diversity most important

### 3.2 Register Models in Azure ML

```bash
# From Azure ML workspace
az ml model create \
  --name avars-isolation-forest \
  --type custom_model \
  --path models/isolation_forest_model.pkl \
  --resource-group avars-rg \
  --workspace-name avars-ml

az ml model create \
  --name avars-random-forest \
  --type custom_model \
  --path models/random_forest_model.pkl \
  --resource-group avars-rg \
  --workspace-name avars-ml
```

### 3.3 Set Up Azure OpenAI Connection

```bash
# Create Azure OpenAI resource
az cognitiveservices account create \
  --name avars-openai \
  --resource-group avars-rg \
  --kind OpenAI \
  --sku S0 \
  --location eastus

# Get API key
API_KEY=$(az cognitiveservices account keys list \
  --name avars-openai \
  --resource-group avars-rg \
  --query key1 -o tsv)

# Store in Key Vault
az keyvault secret set \
  --vault-name avars-lab-kv-XXXX \
  --name openai-api-key \
  --value $API_KEY
```

### 3.4 Deploy GPT-4o Model

```bash
# In Azure OpenAI Studio:
# 1. Go to Model Deployments
# 2. Create new deployment
# 3. Model: gpt-4o
# 4. Deployment name: gpt-4-prod
# 5. Instance count: 1 (for lab)
# 6. Deployment capacity: Standard (auto-scale: 0-20)
```

---

## Phase 4: Automated Response (SOAR)

### 4.1 Create Logic App for Incident Response

```bash
# Create Logic App
az logicapp create \
  --resource-group avars-rg \
  --name avars-incident-response \
  --definition logic-apps/incident_response_workflow.json
```

The workflow includes a Human-in-the-Loop (HITL) approval gate for critical alerts:
- **Approve**: continue to firewall block and remediation
- **Ignore/Reject**: stop containment and send reviewer notification

> Connector note: configure Outlook and Approvals/Teams connections in the Logic App after deployment.

### 4.2 Configure Sentinel Alert Rule

In Azure Portal:

```
1. Microsoft Sentinel > Analytics
2. Create new rule > Scheduled query rule
3. Name: "SQL-Injection-Detection"
4. Copy KQL from scripts/kql/mitre_mapping.kql Query 1
5. Query frequency: PT5M (5 minutes)
6. Query period: PT30M (30 minutes)
7. Threshold: > 0
8. Set severity: High
9. Incident settings: Create incident
10. Automation: Connect to Logic App "avars-incident-response"

Alternative (recommended for false-positive control):
1. Create another Scheduled Query Rule using `scripts/kql/false_positive_whitelist_analytics_rule.md`
2. Paste its KQL query (watchlist-aware)
3. Keep incident creation enabled
4. Connect automation to Logic App `avars-incident-response`

Or use the non-interactive CLI automation above to create this rule directly.
```

### 4.3 Configure Jira Integration

```bash
# Get Jira API token
# Instructions: https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/

# Store in Key Vault
az keyvault secret set \
  --vault-name avars-lab-kv-XXXX \
  --name jira-api-token \
  --value YOUR_JIRA_TOKEN
```

### 4.4 Test Automated Response

```bash
# Trigger a test incident
# Run credential stuffing attack again:
python scripts/attacks/credential_stuffing.py http://<JUICE_SHOP_URL> --delay 0.2

# Monitor in Sentinel:
# 1. Check Incidents and alerts
# 2. Verify Logic App execution
# 3. Check Jira for new issue creation
# 4. Verify Firewall rule was added
```

**Expected Actions**:
- ✓ High-severity alert created in Sentinel
- ✓ AI analysis generated via OpenAI
- ✓ HITL decision request sent to SOC reviewer
- ✓ Jira ticket created with incident details (on approval)
- ✓ Firewall rule blocks source IP (on approval)
- ✓ Email notification sent to security team

### 4.5 Configure Log Integrity Hash References (Key Vault)

Store trusted hash references used by GAN/log-integrity validation in Key Vault.

```bash
az keyvault secret set \
  --vault-name avars-lab-kv-XXXX \
  --name log-hash-gold-manifest \
  --value "<sha256-or-signed-manifest>"
```

Use this value as the trusted baseline when validating telemetry integrity before ML inference.

---

## Verification Checklist

### Phase 1 Verification
- [ ] Resource group created with all resources
- [ ] Hub-and-Spoke network topology deployed
- [ ] Azure Firewall operational and logging
- [ ] Log Analytics workspace receiving data
- [ ] Sentinel enabled and data connectors active

### Phase 2 Verification
- [ ] Attack scripts execute without errors
- [ ] Firewall logs visible in Log Analytics
- [ ] Sentinel detection rules creating alerts
- [ ] KQL queries returning results
- [ ] `ip_whitelist` watchlist suppresses known-safe IP alerts
- [ ] MITRE ATT&CK techniques correctly mapped

### Phase 3 Verification
- [ ] ML notebook runs end-to-end
- [ ] Models trained with ROC-AUC >= 0.90
- [ ] Feature engineering produces 14 features
- [ ] Anomalies detected in test data
- [ ] Models saved to Azure ML

### Phase 4 Verification
- [ ] Logic Apps workflow successfully triggered
- [ ] Azure OpenAI returns executive summaries
- [ ] HITL approval gate sends Approve/Ignore request
- [ ] Ignore path prevents firewall block
- [ ] Jira tickets created automatically
- [ ] Firewall rules updated via API
- [ ] Email/Slack notifications sent
- [ ] Key Vault contains trusted log hash baseline secret

---

## Troubleshooting

### Issue: Terraform State Lock

```bash
# If stuck on resource creation:
terraform force-unlock LOCK_ID
```

### Issue: Firewall Rules Not Applied

```bash
# Check firewall policy
az network firewall policy show \
  --resource-group avars-rg \
  --name avars-lab-fw-policy

# Recreate if necessary
terraform destroy -target azurerm_firewall.avars
terraform apply
```

### Issue: Log Analytics Not Receiving Logs

```bash
# Verify diagnostic settings
az monitor diagnostic-settings list \
  --resource /subscriptions/YOUR_SUBSCRIPTION_ID/resourceGroups/avars-rg/providers/Microsoft.Network/azureFirewalls/avars-lab-fw

# Re-enable if necessary
az monitor diagnostic-settings create \
  --resource-group avars-rg \
  --name firewall-logs \
  --resource-type Microsoft.Network/azureFirewalls \
  --resource avars-lab-fw \
  --logs-destination-type LogAnalyticsWorkspace \
  --workspace /subscriptions/YOUR_SUBSCRIPTION_ID/resourcegroups/avars-rg/providers/microsoft.operationalinsights/workspaces/avars-lab-law
```

### Issue: Models Not Training

```bash
# Check Python version
python --version  # Should be 3.9+

# Reinstall dependencies
pip install --upgrade scikit-learn pandas numpy
```

---

## Cost Estimation

### Monthly Costs (Approximate)

| Resource | SKU | Hours/Month | Cost |
|----------|-----|-----------|------|
| Firewall | Standard | 730 | $1.25/hr = **$912.50** |
| Kali VM | Standard_B2s | 730 | $0.10/hr = **$73** |
| Container Instances | 2 x 1vCPU, 1GB | 730 | $0.0000125/sec = **$32.40** |
| Log Analytics | 5GB/day | 730 | ~**$25-50** |
| Sentinel | 100GB/day | 730 | ~**$20** |
| **Total** | | | **~$1,063-1,088/month** |

### Cost Optimization
1. **Reduce VM size**: Use `Standard_B1s` (~$7/month) instead of B2s
2. **Use Reserved Instances**: 1-year = 30% discount
3. **Shared Firewall**: If applicable, split costs across team
4. **Auto-shutdown Kali VM**: Use Azure Policy to turn off after hours

### Lab Mode (Minimal Cost)
- Kali: Auto-shutdown after 4 hours daily = **$18/month**
- Firewall: Keep on for logging = **$912/month**
- Total Minimal: **~$1,000/month**

---

## Security Best Practices

### Network Security
- ✓ Hub-Spoke isolates honeypots from production
- ✓ NSGs restrict traffic by source/destination
- ✓ Azure Firewall centralized security
- ✓ No public access to honeypots except ports 80/443/22

### Data Protection
- ✓ API keys stored in Key Vault (not in code)
- ✓ Service Principal with least privilege
- ✓ Log retention: 30 days (configurable)
- ✓ Sensitive data encrypted at rest

### Access Control
- ✓ RBAC on all resources
- ✓ Kali VM accessible only via SSH (keys recommended)
- ✓ Sentinel read-only to analysts
- ✓ Admin access limited to service principal

### Compliance
- ✓ Audit logs for all changes
- ✓ Full attack/response chain logged
- ✓ MITRE ATT&CK mapping for compliance
- ✓ Incident response documentation automated

---

## Next Steps & Enhancements

### Phase 5 (Future)
- [ ] Container Registry for custom images
- [ ] AKS cluster for advanced attack scenarios
- [ ] Automated Slack notifications
- [ ] Grafana dashboards for visualization
- [ ] GitHub Actions for CI/CD

### Phase 6 (Production Hardening)
- [ ] WAF rules for API protection
- [ ] DDoS protection enabled
- [ ] Multi-region failover
- [ ] Annual security certification

---

## Contact & Support

- **Questions?**: File an issue on GitHub
- **Security Issues**: Report privately
- **Feedback**: Suggestions welcome

---

**Last Updated**: February 2026  
**Version**: 1.0  
**Status**: Production Ready
