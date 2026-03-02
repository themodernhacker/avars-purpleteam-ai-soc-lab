# A.V.A.R.S Real-Time Security War Room

## 🎯 Overview

The A.V.A.R.S Security War Room is a comprehensive, real-time monitoring and visualization platform designed for CISO-level threat detection, compliance tracking, and incident response orchestration. Built with Grafana, Prometheus, Loki, and AlertManager, it provides:

- **14 Live Dashboards**: Threat maps, C2 detection, compliance health, incident responses
- **25+ Alert Rules**: NIST SP 800-53/ISO 27001 control mapping, ransomware, lateral movement, data exfiltration
- **5-Second Integration**: Pulls from Microsoft Sentinel, LSTM model, Azure OpenAI, KEV
- **AI-Powered Insights**: LSTM confidence scores, predictive trending, anomaly detection
- **Executive Visibility**: Compliance gauges, MTTR metrics, geographic attack distribution

---

## 📊 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    THREAT DETECTION LAYER                        │
├─────────────────────────────────────────────────────────────────┤
│ • Microsoft Sentinel (SIEM)         → SecurityAlert tables       │
│ • LSTM C2 Detector                  → Confidence scores          │
│ • Azure Firewall                    → Network flows              │
│ • Endpoint Detection Response (EDR)  → Behavioral analytics      │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│              OBSERVABILITY & AGGREGATION LAYER                   │
├─────────────────────────────────────────────────────────────────┤
│ Prometheus (Metrics)    ─→ LSTM model health, alert counts       │
│ Loki (Logs)            ─→ Audit trails, SIEM events             │
│ Azure Log Analytics    ─→ Sentinel queries, control mapping      │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│               ALERTING & ROUTING LAYER                           │
├─────────────────────────────────────────────────────────────────┤
│ AlertManager          → Aggregates alerts by severity/component  │
│ Slack/Teams/Email     → Routes to on-call teams                 │
│ PagerDuty/OpsGenie    → Incident escalation                     │
│ Custom Webhooks       → Logic Apps, SOAR platforms              │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│              VISUALIZATION & RESPONSE LAYER                      │
├─────────────────────────────────────────────────────────────────┤
│ Grafana Dashboard (War Room)                                    │
│  ├─ Panel 1: Live Activity (24h incidents)                      │
│  ├─ Panel 2: Critical/High Severity Alerts                      │
│  ├─ Panel 3: Attack Severity Distribution (pie)                 │
│  ├─ Panel 4: LSTM C2 Confidence Scores (time series)            │
│  ├─ Panel 5: Geographic Heat Map (attack sources)               │
│  ├─ Panel 6: Compromised User Accounts (table)                  │
│  ├─ Panel 7: Automated Response Rate (gauge)                    │
│  ├─ Panel 8: NIST Control Coverage (bar chart)                  │
│  ├─ Panel 9: Compliance Health Score (gauge)                    │
│  ├─ Panel 10: Mean Time to Response (MTTR)                      │
│  ├─ Panel 11: Top Attack Techniques (MITRE ATT&CK)              │
│  ├─ Panel 12: Recent Critical Incidents (logs)                  │
│  ├─ Panel 13: Endpoint Security Status                          │
│  └─ Panel 14: ML Model Performance Metrics                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start (Docker Compose)

### Prerequisites
- Docker & Docker Compose installed
- Azure credentials (Service Principal for Sentinel integration)
- Environment variables configured

### Step 1: Clone and Navigate
```bash
cd "d:\Project A.V.A.R.S\dashboards"
```

### Step 2: Configure Environment Variables
Create a `.env` file in the `dashboards/` directory:

```bash
# Azure Authentication
AZURE_CLIENT_ID=<your-service-principal-client-id>
AZURE_CLIENT_SECRET=<your-service-principal-client-secret>
AZURE_TENANT_ID=<your-azure-tenant-id>
AZURE_SUBSCRIPTION_ID=<your-subscription-id>
LOG_ANALYTICS_WORKSPACE_ID=<your-workspace-id>

# Grafana
GRAFANA_ADMIN_PASSWORD=<secure-password>

# Slack Integration
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Microsoft Teams
MS_TEAMS_WEBHOOK_URL=https://outlook.webhook.office.com/webhookb2/YOUR/URL

# PagerDuty
PAGERDUTY_SERVICE_KEY_CRITICAL=<critical-service-key>
PAGERDUTY_SERVICE_KEY_INCIDENT=<incident-service-key>

# OpsGenie
OPSGENIE_API_KEY=<your-opsgenie-api-key>

# SMTP (for email alerts)
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USER=alerts@your-domain.com
SMTP_PASSWORD=<app-password>
```

### Step 3: Start the Stack
```bash
docker-compose -f docker-compose-grafana-stack.yml up -d
```

### Step 4: Verify Services
```bash
# Check container status
docker-compose -f docker-compose-grafana-stack.yml ps

# Expected output:
# CONTAINER ID   STATUS          NAMES
# ...            healthy         avars-grafana-warroom
# ...            healthy         avars-prometheus
# ...            healthy         avars-loki
# ...            running         avars-alertmanager
# ...            running         avars-promtail
```

### Step 5: Access Grafana
- **URL**: http://localhost:3000
- **Default User**: secadmin
- **Password**: *$GRAFANA_ADMIN_PASSWORD* (from .env)

---

## 📈 Dashboard Walkthrough

### Panel 1: Live Threat Activity (Last 24h)
- **Type**: Stat card with thresholds
- **Query**: `count(SecurityAlert where TimeGenerated > ago(24h))`
- **Thresholds**:
  - Green: 0-9 incidents
  - Yellow: 10-19 incidents
  - Orange: 20-49 incidents
  - Red: 50+ incidents
- **Use Case**: Quickly assess threat velocity

### Panel 2: Critical & High Severity Alerts
- **Type**: Stat card (red when > 0)
- **Query**: Filters SecurityAlert by severity
- **Action**: Click card → Triggers incident response workflow
- **SLA**: Must acknowledge within 5 minutes

### Panel 3: Incident Severity Distribution
- **Type**: Pie chart
- **Data**: 7-day rolling window
- **Color Scheme**:
  - Red: Critical
  - Orange: High
  - Yellow: Medium
  - Green: Low
- **Use Case**: Identify trending attack patterns

### Panel 4: LSTM C2 Detection Confidence Scores
- **Type**: Time series with alert threshold (0.80)
- **Query**: `avg(C2_Probability) by time_bucket('5m')`
- **Thresholds**:
  - Green: <0.50 (safe)
  - Yellow: 0.50-0.79 (suspicious)
  - Red: 0.80+ (confirmed C2)
- **Integration**: Linked to Logic App automation
- **SLA**: Alert fires at >0.95 confidence

### Panel 5: Geographic Attack Distribution (Heat Map)
- **Type**: World map with color intensity
- **Data**: Geolocated source IPs from SecurityAlert
- **Color**: Green→Yellow→Orange→Red (intensity)
- **Use Case**: Identify geographic threat actors, DDoS origins
- **Example**: If all traffic from Crimea, China, North Korea → HIGH RISK

### Panel 6: Identity Attacks (Compromised Users)
- **Type**: Table with sorting
- **Schema**: [User, AttackCount, MaxSeverity, LastSeen]
- **Auto-Action**: AttackCount > 10 → Disable account (Logic App)
- **Columns**: Sortable by AttackCount (descending)
- **Use Case**: Incident commander identifies users to revoke

### Panel 7: Automated Response Rate
- **Type**: Gauge (0-100%)
- **Calculation**: (Automated Responses / Total Alerts) × 100
- **Thresholds**:
  - Red: <50% (manual response heavy)
  - Yellow: 50-79%
  - Green: 80%+ (best practice)
- **Goal**: Drive toward 95%+ automation rate

### Panel 8: NIST Control Coverage (Bar Chart)
- **Type**: Horizontal bar chart
- **Data**: Count of incidents per NIST SP 800-53 control
- **Example Bars**:
  - AC-2 (Account Management): 47 tests
  - SI-4 (Network Monitoring): 132 tests
  - IA-5 (Password Policy): 18 tests
- **Use Case**: Identify over/under-tested controls

### Panel 9: Compliance Health Score
- **Type**: Gauge (0-100%)
- **Calculation**: (Controls Tested / 22 total NIST controls) × 100
- **Thresholds**:
  - Red: <60% (audit failing)
  - Orange: 60-75%
  - Yellow: 75-90%
  - Green: 90%+ (audit passing)
- **Refresh**: Every 5 minutes
- **Use Case**: CISO dashboard metric

### Panel 10: Mean Time to Response (MTTR)
- **Type**: Stat card (minutes)
- **Query**: `avg(ResponseTimeMinutes) where TimeGenerated > ago(7d)`
- **Benchmark**:
  - Green: <15 min (excellent)
  - Yellow: 15-30 min
  - Orange: 30-60 min
  - Red: >60 min (SLA breach)
- **Target**: <5 min for critical incidents

### Panel 11: Top Attack Techniques (MITRE ATT&CK)
- **Type**: Table (sortable)
- **Schema**: [Technique, AttackCount, Severity]
- **Example**: 
  - T1071 (C2 Protocol): 24 detections
  - T1110 (Brute Force): 156 detections
  - T1190 (Exploit): 8 detections
- **Use Case**: Identify top tactics to defend against

### Panel 12: Recent Critical Incidents (Logs)
- **Type**: Table with vertical scroll
- **Data**: Last 50 critical incidents (last 24h)
- **Columns**: [Timestamp, Alert, User, Source IP, Severity]
- **Action**: Click row → Jump to Sentinel incident
- **Retention**: 90 days

### Panel 13: Endpoint Security Status
- **Type**: Stat card (%)
- **Query**: Healthy agents / Total agents
- **Threshold**:
  - Green: >95% healthy
  - Yellow: 80-95%
  - Red: <80% (degraded coverage)
- **Use Case**: Identify patching gaps

### Panel 14: ML Model Performance
- **Type**: Table (static metrics)
- **Metrics**:
  - ROC-AUC Score: 0.95 (target >0.90)
  - Precision: 0.92 (target >0.85)
  - Recall: 0.88 (target >0.85)
  - F1 Score: 0.90 (target >0.85)
- **Refresh**: Daily (after model retraining)
- **Use Case**: Data science team monitors model drift

---

## 🔔 Alert Rules (25+)

### Critical Severity (Incident Commander Paged)

| Alert Name | Condition | Action |
|-----------|-----------|--------|
| **CriticalC2DetectionHighConfidence** | C2 confidence > 0.95 | Page incident commander, disable account, revoke sessions |
| **RansomwareIndicators** | File encryption rate > 100/min OR boot modifications | Page incident commander, isolate endpoint, disable account |
| **ZeroTrustPolicyViolation** | Any violation of network policy | Page security ops, block source IP, revoke session |
| **LSTMModelInferenceServiceDown** | Model service unavailable > 2 min | Page data science, enable static C2 signatures fallback |

### High Severity (Security Operations Page)

| Alert Name | Condition | Action |
|-----------|-----------|--------|
| **HighRateAuthenticationFailures** | >10 failed auth/sec for 2 min | Block source IP, trigger MFA challenge, notify user |
| **LateralMovementDetected** | >1 lateral move attempt/min | Isolate affected systems, revoke admin sessions |
| **PrivilegeEscalationAttempt** | Any privilege escalation | Revoke escalated privileges, force password reset |
| **SQLInjectionAttempt** | Any SQL injection detected | Block source IP, WAF rule update, notify application owner |
| **AutomatedResponseFailure** | >10% of responses failing | Page, create incident, require manual intervention |

### Medium Severity (Security Team Notified)

| Alert Name | Condition | Action |
|-----------|-----------|--------|
| **DataExfiltrationIndicators** | High volume + multiple countries | Enable DLP, request user confirmation |
| **EndpointSecurityGap** | Healthy endpoints < 95% | Schedule patching, escalate to IT |
| **DDosIndicators** | >10k requests/min + high latency | Rate limit, WAF update, notify network team |
| **ComplianceSLABreach** | <1 hour to remediation deadline | Escalate to compliance officer |
| **LSTMModelAccuracyDegradation** | Accuracy < 85% | Queue model retraining, use fallback |

### Low Severity (Email Digest)

| Alert Name | Condition | Action |
|-----------|-----------|--------|
| **AnomalousUserSignIn** | Risk score > 0.70 | Monitor, request MFA verification |
| **ComplianceCoverageTrendingDown** | Projected < 60% coverage | Email compliance team for planning |
| **ModelDriftDetected** | Distribution JS divergence > 0.3 | Schedule model update during maintenance |

---

## 🔗 Integration Points

### Azure Sentinel
- **Connection**: Azure Monitor datasource
- **Queries**: KQL queries in `nist-iso-control-mapping.kql`
- **Latency**: 5-minute refresh (real-time dashboards)
- **Auth**: Service Principal (Azure AD)

### LSTM C2 Detector
- **Connection**: Prometheus scrape (localhost:5000)
- **Metrics**: 
  - `c2_probability` (0-1 score)
  - `c2_inference_duration_ms` (latency)
  - `c2_samples_processed_total` (throughput)
- **Threshold Alert**: >0.80 confidence → Critical

### Azure OpenAI (Compliance Reporting)
- **Used by**: Logic Apps automation
- **Model**: GPT-4 / GPT-4o
- **Prompt**: "Analyze [incident] against NIST SP 800-53 controls"
- **Output**: Compliance audit report (auto-generated)

### Logic Apps (Incident Response)
- **Trigger**: SecurityAlert from Sentinel
- **Automation**: Account disable → Session revoke → Password reset
- **Notification**: Send automated response summary to Grafana

---

## 🛠️ Configuration

### Azure Credentials Setup

1. **Create Service Principal**:
   ```bash
   az ad sp create-for-rbac --name avars-monitoring \
     --role "Log Analytics Reader" \
     --scope /subscriptions/{subscription-id}
   ```

2. **Grant Permissions**:
   - Log Analytics: Read access
   - Key Vault: Get secret access (for API keys)
   - Sentinel: Read incident data

3. **Store in `.env`**:
   ```bash
   AZURE_CLIENT_ID=<app-id>
   AZURE_CLIENT_SECRET=<password>
   AZURE_TENANT_ID=<tenant-id>
   AZURE_SUBSCRIPTION_ID=<subscription-id>
   ```

### Slack Integration

1. **Create Webhook**:
   - Go to https://api.slack.com/apps
   - Create new app: "AVARS Alerts"
   - Enable Incoming Webhooks
   - Create channels: #critical-security-incidents, #soc-incidents, #security-team
   - Get webhook URL for each channel

2. **Update `.env`**:
   ```bash
   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX
   ```

3. **Test Alert**:
   ```bash
   curl -X POST $SLACK_WEBHOOK_URL \
     -H 'Content-Type: application/json' \
     -d '{"text":"🧪 Grafana alert test successful!"}'
   ```

### PagerDuty (On-Call Escalation)

1. **Create PagerDuty Service**:
   - Service name: "A.V.A.R.S Security"
   - Escalation policy: InfoSec on-call
   - Integration: Alertmanager

2. **Get Service Keys**:
   ```bash
   # Critical service (immediate page)
   PAGERDUTY_SERVICE_KEY_CRITICAL=<integration-key>
   
   # Standard incidents
   PAGERDUTY_SERVICE_KEY_INCIDENT=<integration-key>
   ```

---

## 📊 Performance & Scaling

| Component | Capacity | Scaling Strategy |
|-----------|----------|-------------------|
| **Grafana** | 10,000 dashboard views/day | Horizontal (multiple instances + reverse proxy) |
| **Prometheus** | 1M metrics/10s scrape | Retention: 15 days (adjust as needed) |
| **Loki** | 100GB/day log ingest | Retention: 30 days (archive older logs) |
| **AlertManager** | 10,000 alerts/min | Multiple replicas for HA |

### Optimization Tips

1. **Reduce Prometheus retention**:
   ```bash
   # Current: 15 days, adjust if disk constrained
   docker-compose exec prometheus promtool tsdb create-blocks-from-wal /prometheus
   ```

2. **Archive old Loki logs**:
   ```bash
   # Move logs >90 days old to Azure Blob Storage
   loki_archive_schedule: "0 2 * * 0"  # Weekly
   ```

3. **Dashboard caching**:
   - Enable Grafana result caching
   - Set cache TTL: 5 min for metrics, 10 min for logs

---

## 🧪 Testing & Validation

### Test C2 Detection Alert
```bash
# Simulate high C2 confidence score
curl -X POST http://localhost:9091/metrics/c2_probability \
  -d 'c2_probability{instance="test"} 0.92'

# Expected: AlertManager → Slack → Critical incident channel
```

### Test Automated Response
```bash
# Trigger a synthetic SecurityAlert in Sentinel
# → Logic App activates
# → User account disabled
# → Compliance report generated
# → Check Power BI dashboard updated
```

### Validate KQL Queries
```kql
// Run in Sentinel → Logs blade
nist_iso_control_mapping
| where TimeGenerated > ago(24h)
| summarize ControlsTested=dcount(NISTControl) by AlertName
```

---

## 📞 Support & Escalation

**War Room Contacts**:
- **CISO**: Instant Slack notification (critical only)
- **Security Operations**: PagerDuty + Slack (high & critical)
- **Incident Commander**: On-call phone number + Teams call
- **Data Science**: Email digest (model health alerts)

**On-Call Rotation**:
- CISO: Weekdays 8am-6pm, on-call Fri-Mon (rotating)
- SOC: 24/7 coverage (3 shift model)
- Incident Commander: On-call weekly rotation

---

## 🔐 Security Best Practices

1. **Limit Grafana Access**: Use Azure AD SSO, RBAC for dashboards
2. **Secure Secrets**: Store API keys in Azure Key Vault (not .env)
3. **Alert Visibility**: Encrypt alerts in transit (HTTPS only)
4. **Audit Logging**: Enable CloudAudit for all modifications
5. **Webhook Validation**: Verify AlertManager webhook signatures

---

## 📝 Maintenance

### Weekly
- Review LSTM model performance (Panel 14)
- Check compliance coverage (Panel 9) > 90%
- Verify MTTR trend (Panel 10) improving

### Monthly
- Archive old logs from Loki
- Review alert fatigue (over-alerting?)
- Update dashboard documentation
- Test incident response workflow

### Quarterly
- Audit who has Grafana admin access
- Review compliance control mapping (KQL queries)
- Retrain LSTM model with new attack data
- Update alert thresholds based on environment changes

---

## 📚 References

- **NIST SP 800-53**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
- **ISO 27001**: https://www.iso.org/standard/54534.html
- **MITRE ATT&CK**: https://attack.mitre.org/
- **Grafana Docs**: https://grafana.com/docs/
- **Prometheus Docs**: https://prometheus.io/docs/
- **AlertManager**: https://prometheus.io/docs/alerting/latest/overview/

---

## 🎯 Success Criteria

Your A.V.A.R.S war room is production-ready when:

✅ **Grafana dashboard loads in <2 seconds**
✅ **Alerts fire within 60 seconds of incident occurrence**
✅ **LSTM model confidence scores update every 5 minutes**
✅ **Compliance health score >= 90%**
✅ **MTTR trending downward (target: <5 min for critical)**
✅ **No manual dashboard refreshes needed (auto-refresh enabled)**
✅ **All 14 panels render data without errors**
✅ **AlertManager routes to correct Slack channels**
✅ **Logic Apps triggered by alerts complete within 2 min**

---

**Deployment Date**: [Your Date]
**Last Updated**: [Current Date]
**Owner**: Security Architecture Team
**Review Frequency**: Monthly

