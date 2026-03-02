# Project A.V.A.R.S - Architecture & Design Document

## Executive Summary

**Project A.V.A.R.S** (AI-Verified Automated Response System) is an enterprise-grade cloud security lab demonstrating:
- **DevSecOps Excellence**: Infrastructure as Code (Terraform)
- **Threat Detection**: Real attacks + MITRE ATT&CK mapping
- **AI Integration**: Generative AI (GPT-4o) + Predictive ML (Random Forest/Isolation Forest)
- **Automated Response**: SOAR with Logic Apps
- **Log Integrity Assurance**: Key Vault-stored gold hash references for GAN validation
- **Complete Kill-Chain**: Attack → Detection → Analysis → Response

---

## 1. System Architecture Overview

### 1.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Azure Cloud (East US)                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              HUB VIRTUAL NETWORK (10.0.0.0/16)            │  │
│  │  ┌──────────────────────────────────────────────────┐   │  │
│  │  │   AZURE FIREWALL (Public IP)                     │   │  │
│  │  │   - All traffic filtered & logged               │   │  │
│  │  │   - DENY rules for identified threats           │   │  │
│  │  │   - Threat Intelligence enabled                 │   │  │
│  │  └──────────────────────────────────────────────────┘   │  │
│  │       │                           │                      │  │
│  │       ▼                           ▼                      │  │
│  │  ┌─────────────┐        ┌──────────────────┐           │  │
│  │  │ Log         │        │ Key Vault        │           │  │
│  │  │ Analytics   │        │ (Secrets)        │           │  │
│  │  │ Workspace   │        │                  │           │  │
│  │  │ 30-day      │        └──────────────────┘           │  │
│  │  │ retention   │                                         │  │
│  │  └─────────────┘                                         │  │
│  │       │                                                  │  │
│  │       ▼                                                  │  │
│  │  ┌────────────────────────────────────────────┐        │  │
│  │  │   MICROSOFT SENTINEL (SIEM)                │        │  │
│  │  │   - KQL queries for threat hunting        │        │  │
│  │  │   - Alert rules (SQL Inj, Brute Force)   │        │  │
│  │  │   - MITRE ATT&CK workbooks               │        │  │
│  │  │   - Incident correlation                 │        │  │
│  │  └────────────────────────────────────────────┘        │  │
│  │       │                                                  │  │
│  │       ▼                                                  │  │
│  │  ┌────────────────────────────────────────────┐        │  │
│  │  │   LOGIC APPS (SOAR Orchestration)        │        │  │
│  │  │   - Triggered by Sentinel alerts         │        │  │
│  │  │   - Calls Azure OpenAI for analysis      │        │  │
│  │  │   - HITL approval (Approve/Ignore) gate  │        │  │
│  │  │   - Executes remediation after approval  │        │  │
│  │  └────────────────────────────────────────────┘        │  │
│  └──────────────────────────────────────────────────────────┘  │
│         │                                 │                     │
│         │                                 │                     │
│    PEERING                            PEERING                   │
│         │                                 │                     │
│  ┌──────┴──────┐                  ┌──────┴──────┐              │
│  │             │                  │             │              │
│  ▼             ▼                  ▼             ▼              │
│                                                                   │
│  ┌─────────────────────────┐  ┌──────────────────────────┐   │
│  │ SPOKE 1: HONEY-NET      │  │ SPOKE 2: MANAGEMENT     │   │
│  │ (10.1.0.0/16)           │  │ (10.2.0.0/16)           │   │
│  │                         │  │                          │   │
│  │ ┌─────────────────────┐ │  │ ┌────────────────────┐  │   │
│  │ │ ACI Container 1     │ │  │ │ Kali Linux VM      │  │   │
│  │ │ OWASP Juice Shop    │ │  │ │ Attack Platform   │  │   │
│  │ │ :3000 (Honeypot)    │ │  │ │ - Credential      │  │   │
│  │ │                     │ │  │ │   Stuffing        │  │   │
│  │ └─────────────────────┘ │  │ │ - SQL Injection   │  │   │
│  │                         │  │ │ - Reconnaissance  │  │   │
│  │ ┌─────────────────────┐ │  │ │ - Azure Monitor   │  │   │
│  │ │ ACI Container 2     │ │  │ │   Agent           │  │   │
│  │ │ SSH Honeypot        │ │  │ │ (logs captured)   │  │   │
│  │ │ (Cowrie Port 22)    │ │  │ └────────────────────┘  │   │
│  │ │                     │ │  │                          │   │
│  │ └─────────────────────┘ │  └────────────────────────┘  │   │
│  └─────────────────────────┘                               │   │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘

                              EXTERNAL
                           (Simulated Attacker)
```

### 1.2 Data Flow Architecture

```
ATTACK SIMULATION (eJPT Skills)
              │
              ▼
┌─────────────────────────────────────────┐
│  Kali VM Executes Attack               │
│  - Credential Stuffing                 │
│  - SQL Injection                       │
│  - Port Scanning                       │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Honeypots Receive & Log                │
│  - Juice Shop (HTTP /401 /403)         │
│  - SSH Honeypot (Connection Attempts)  │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Firewall Captures & Logs               │
│  - Network traffic                      │
│  - Application rules                    │
│  - Threat intelligence matches          │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Azure Monitor Agent (AMA)              │
│  - Streams logs to Log Analytics       │
│  - 50MB aggregate (free tier OK)       │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Microsoft Sentinel (Phase 2)           │
│  - Ingests firewall logs               │
│  - Applies KQL detection rules         │
│  - Suppresses known-safe IPs (watchlist) │
│  - Maps to MITRE ATT&CK               │
│  - Creates incidents                   │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  ML Model Scoring (Phase 3)             │
│  - Isolation Forest (anomaly)           │
│  - Random Forest (exfiltration risk)   │
│  - GAN checks against trusted hash refs │
│  - Anomaly Score: 0.0-1.0              │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Azure OpenAI Analysis (Phase 3)        │
│  - Digests raw logs                    │
│  - Generates Executive Summary          │
│  - Suggests Remediation Script         │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Logic App Automation (Phase 4)         │
│  - Blocks IP at Firewall               │
│  - Isolates Container                  │
│  - Creates Jira Ticket                 │
│  - Sends Notifications                 │
└─────────────────────────────────────────┘
```

---

## 2. Component Architecture

### 2.1 Network Design (Hub-and-Spoke)

**Why Hub-and-Spoke?**
- Centralized security (firewall in hub)
- Hierarchical traffic control
- Scalable (add more spokes easily)
- Cost-efficient (single firewall)
- Enterprise-grade design pattern

**Advantages in Lab Context:**
- Demonstrates enterprise architecture
- Separates concerns (security ops vs attack simulation)
- Easy to add new environments
- Clear security boundaries

### 2.2 Security Zones

```
┌─ ZONE 1: Public/DMZ (Honeypots) ─────────────┐
│ Purpose: Accept attacks, capture logs        │
│ Resources: Juice Shop, SSH Honeypot         │
│ Firewall Rules: ALLOW inbound HTTP/SSH       │
│ Data: Malicious traffic (expected)           │
└──────────────────────────────────────────────┘

┌─ ZONE 2: Management/Attack (Kali) ──────────┐
│ Purpose: Execute penetration tests          │
│ Resources: Kali Linux VM, Azure Monitor     │
│ Firewall Rules: ALLOW outbound to honeypots │
│ Data: Attack payloads, audit logs           │
└──────────────────────────────────────────────┘

┌─ ZONE 3: Security Operations (Hub) ─────────┐
│ Purpose: Monitor, detect, respond          │
│ Resources: Sentinel, Log Analytics, Logic   │
│ Firewall Rules: DENY by default, ALLOW     │
│             specific patterns               │
│ Data: Detections, incidents, artifacts      │
└──────────────────────────────────────────────┘
```

### 2.3 Azure Firewall Configuration

**Rules Structure:**
```
Priority   Name                  Rule Type    Action
    100   AllowDNS             Network       ALLOW  UDP/53 any→any
    110   BlockExfiltration    Network       DENY   TCP * → suspicious IPs
    120   AllowHTTP            Application  ALLOW  domain=*.microsoft.com
    130   DetectSQLinject      Application  ALLOW  (with logging)
    ...
  65000   DenyAll              Network       DENY   any→any
```

**Logging & Threat Intel:**
- Diagnostic Settings → Log Analytics Workspace (100% sampling)
- Threat Intelligence enabled (blocks known malicious IPs)
- Alert rules at 10+ denied packets per second

---

## 3. Detection Architecture (MITRE ATT&CK Mapping)

### 3.1 Mapped Techniques

| Technique | MITRE ID | Attack Type | KQL Query |
|-----------|----------|------------|-----------|
| Brute Force | T1110 | Credential Stuffing | Query 2 |
| Exploit Public App | T1190 | SQL Injection | Query 1 |
| Network Scanning | T1046 | Port Reconnaissance | Query 3 |
| Gather Host Info | T1592 | Reconnaissance Probing | Query 4 |
| Gather Identity | T1589 | User Enumeration | Query 5 |
| Exfiltration | T1020 | Out-of-Band Data Transfer | ML Model |

### 3.2 KQL Query Architecture

**Design Principles:**
1. **Specificity**: Reduce false positives (σ-like detection)
2. **Correlation**: Multiple indicators increase confidence
3. **Timing**: 5-minute query window for real-time
4. **Normalization**: Standardize field names across sources
5. **Whitelist Control**: Sentinel watchlists suppress known-safe entities

**Query Layers:**

```
Layer 1: Raw Data Collection
  AzureDiagnostics | where ResourceType == "AZUREFIREWALLS"
           │
           ▼
Layer 2: Feature Extraction
  extend SourceIP = extract(...), BytesSent = toint(...)
           │
           ▼
Layer 3: Aggregation
  summarize Count = count() by SourceIP
           │
           ▼
Layer 4: Anomaly Detection
  where Count > threshold or Behavior deviates from baseline
           │
           ▼
Layer 5: Entity Extraction
  extend EntityIP = SourceIP, TechniqueID = "T1110"
```

---

## 4. Machine Learning Architecture

### 4.1 Feature Engineering Pipeline

**Input Data**: 24 hours of firewall logs (1000+ entries)

**Features Extracted** (14 total):
```
Volume Metrics:
  - total_bytes_sent
  - total_bytes_received
  - max_bytes_per_connection
  - avg_bytes_sent / received
  
Frequency Metrics:
  - connection_count
  - avg_bytes_per_connection
  
Diversity Metrics:
  - unique_destinations
  - unique_ports
  - destination_diversity ratio
  - port_diversity ratio
  
Ratio Metrics:
  - bytes_ratio (sent/received)
  - total_bytes_transferred
```

### 4.2 Isolation Forest Model

**Purpose**: Unsupervised anomaly detection

**Configuration:**
```python
IsolationForest(
    contamination=0.15,     # Expect 15% anomalies
    n_estimators=100,       # Decision trees
    random_state=42,        # Reproducibility
    n_jobs=-1              # Parallel processing
)
```

**Decision Logic:**
- Isolates anomalies by random feature selection
- Shorter isolation paths = anomalies
- Produces anomaly score (lower = more anomalous)

**Use Case**: Detects:
- Unusual volume patterns
- Atypical destination distributions
- Behavioral deviations
- Low-and-slow data exfiltration

### 4.3 Random Forest Classifier

**Purpose**: Supervised classification (normal vs exfiltration)

**Training Data**: Labels from Isolation Forest + domain knowledge

**Configuration:**
```python
RandomForestClassifier(
    n_estimators=100,           # 100 decision trees
    max_depth=10,               # Prevent overfitting
    min_samples_split=5,        # Stability
    class_weight='balanced',    # Handle imbalance
    n_jobs=-1                   # Parallel
)
```

**Output**: Probability that traffic indicates exfiltration

**Evaluation Metrics:**
- ROC-AUC: ≥ 0.92 (target)
- Precision: ≥ 0.85 (minimize false alerts)
- Recall: ≥ 0.80 (catch actual exfiltration)
- F1: Balance precision/recall

---

## 5. Generative AI Integration (LLM Analysis)

### 5.1 Azure OpenAI Integration

**Model**: GPT-4o (latest, multimodal capable)

**Use Cases**:
1. **Incident Summarization**: Raw logs → Executive Summary
2. **Technique Identification**: Log patterns → MITRE ATT&CK mapping
3. **Remediation Script Generation**: Alert → Python/Bash script

**Prompt Structure**:
```
System Prompt:
  "You are a cybersecurity incident analyst. Analyze logs and provide:
   1. Executive Summary (2-3 sentences)
   2. MITRE ATT&CK Technique ID
   3. Python remediation script if applicable"

User Input:
  "Analyze: SourceIP=10.2.1.50, Attack=SQL-Injection, 
   Attempts=45, TimeWindow=5minutes"

Model Output:
  "The source 10.2.1.50 attempted 45 SQL injection attacks targeting
   the application endpoint in 5 minutes, consistent with T1190
   (Exploit Public-Facing Application). Recommended remediation:
   1. Block IP at WAF
   2. Inspect for data exfiltration
   [Python script follows...]"
```

### 5.2 Prompt Engineering for Security

**Strategies**:
- **Few-shot examples**: Provide known attack examples
- **Role-based prompting**: "You are a SOC analyst"
- **Structured outputs**: Request JSON for parsing
- **Context window**: Use last 50 events summarized

**Cost Optimization**:
- Cache common queries (30% cost reduction)
- Batch analysis every 5 minutes
- Use gpt-4-turbo for non-critical alerts
- gpt-4o for critical incidents only

---

## 6. Automation & SOAR (Security Orchestration)

### 6.1 Logic Apps Workflow

**Trigger**: Sentinel Alert

**Routing Logic**:
```
Alert Severity?
  ├─ CRITICAL
  │  ├─ Call Azure OpenAI (analysis)
  │  ├─ Request HITL approval (Approve/Ignore)
  │  ├─ If Approved: Block IP at Firewall
  │  ├─ If Approved: Isolate Container
  │  ├─ If Approved: Create Jira CRITICAL ticket
  │  └─ If Ignored: Notify SOC + keep audit trail
  │
  ├─ HIGH
  │  ├─ Call Azure OpenAI
  │  ├─ Create Jira HIGH ticket
  │  └─ Email security team
  │
  └─ MEDIUM
     ├─ Email notification
     └─ Log to audit trail
```

**Response Time**: <30 seconds (automated path), analyst-dependent for HITL-gated critical path

### 6.2 Remediation Actions

**Action 1: Firewall IP Blocking**
```
PUT /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/azureFirewalls/{fw}
Body: Add DENY rule for source IP
Result: All traffic from attacker dropped
```

**Action 2: Container Isolation**
```
PATCH /subscriptions/{sub}/resourceGroups/...providers/Microsoft.ContainerInstance/containerGroups/{container}
Body: Modify network security group
Result: Container no longer reachable
```

**Action 3: Incident Tracking**
```
POST /jira.company.com/rest/api/3/issue
Body: Incident details + AI analysis + remediation script
Result: Ticket auto-assigns to security team
```

---

## 7. Monitoring & Observability

### 7.1 Key Metrics

**Detection Metrics:**
- Alerts/hour (target: 5-10 for lab)
- False positive rate (target: <10%)
- Detection latency (target: <5 minutes)
- MTTD (Mean Time To Detect): <2 minutes

**Response Metrics:**
- MTTR (Mean Time To Remediate): 30 seconds (automated)
- Action success rate: >95%
- Jira ticket creation latency: <10 seconds

**System Metrics:**
- Firewall throughput: 100+ Mbps
- Log Analytics ingestion: <1 second latency
- Sentinel query performance: <30 seconds
- Logic App execution time: <10 seconds

### 7.2 Dashboards

**Sentinel Dashboard Components**:
- Real-time attack heatmap (source → target IPs)
- MITRE ATT&CK technique distribution
- Incident timeline correlation
- Detection rule performance

**Custom Workbook Queries**:
```kql
// Top attacking IPs (last 24h)
AzureDiagnostics
| where TimeGenerated > ago(24h)
| summarize AttackCount=count() by SourceIP
| top 10 by AttackCount

// Attack types over time
AzureDiagnostics
| where TimeGenerated > ago(24h)
| extend AttackType = case(
    msg_s has "401", "Brute-Force",
    msg_s has "union", "SQLi",
    "Reconnaissance")
| summarize count() by AttackType, bin(TimeGenerated, 1h)
```

---

## 8. Security Posture

### 8.1 Defense-in-Depth Layers

```
Layer 1: Network Perimeter (Firewall)
  ├─ Stateful firewall inspection
  ├─ Application layer filtering
  └─ Threat intelligence integration

Layer 2: Detection (Sentinel + ML)
  ├─ Signature-based (KQL rules)
  ├─ Anomaly-based (Isolation Forest)
  └─ Behavioral (Random Forest)

Layer 3: Response (Logic Apps)
  ├─ Automated blocking
  ├─ Isolation
  └─ Incident tracking

Layer 4: Analysis (Azure OpenAI)
  ├─ Root cause analysis
  ├─ Technique identification
  └─ Remediation guidance

Layer 5: Verification (Continuous Monitoring)
  ├─ Detect bypass attempts
  ├─ Verify remediation
  └─ Update rules
```

### 8.2 Threat Model

**Assumed Threats**:
- External attackers scanning for vulnerabilities
- Credential-based attacks (brute force)
- SQL injection attempts
- Data exfiltration (low-and-slow)
- Internal reconnaissance post-compromise

**Out of Scope**:
- Advanced persistent threats (APT)
- Insider threats with admin access
- Physical security breaches
- Zero-day vulnerabilities

---

## 9. Scalability & Production Readiness

### 9.1 Scale to Production

**Changes Required**:
1. **Replicate across regions**: Multi-geo deployments
2. **Increase retention**: 90+ days on production logs
3. **Add WAF**: Azure Web Application Firewall
4. **Enable DDoS Protection**: Standard or Premium
5. **Implement BCDR**: Backup and disaster recovery
6. **Add Data Residency**: Ensure compliance (GDPR, etc.)

### 9.2 Performance Optimization

**Current Optimization**:
- Firewall: ~1000 Mbps throughput
- Log Analytics: ~10GB/day ingestion
- Sentinel: <30-second query response
- Logic Apps: <5 parallel executions

**Production Upgrade Path**:
- Premium Firewall: 30,000 Mbps
- Log Analytics: Dedicated cluster (100x capacity)
- Sentinel: SOAR connectors (40+ integrations)
- Logic Apps: Managed connector optimization

---

## 10. Compliance & Audit

### 10.1 Audit Trail

**All operations logged to Log Analytics:**
```
- Terraform deployments (via Azure Activity)
- Firewall rule changes (diagnostic logs)
- Sentinel alert creation (built-in)
- Logic App executions (logs)
- OpenAI API calls (audit logs)
- Jira ticket creation (audit)
```

**Query: Show all changes in last 24h**
```kql
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationName in ("Create Firewall Rule", "Update Policy")
| project TimeGenerated, Caller, OperationName, Properties
```

### 10.2 Compliance Mappings

| Framework | Mapped Controls | Evidence |
|-----------|-----------------|----------|
| NIST CSF | ID, DE, RS | Sentinel detection, Logic App response |
| CIS Azure | Logging, Firewalls | Diagnostic settings, firewall config |
| ISO 27001 | A.12 (Logging) | 30-day Log Analytics retention |
| PCI-DSS | AS2 (Logging) | Firewall + application layer logs |

---

## Appendix A: Technology Stack

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| **IaC** | Terraform | 1.5+ | Infrastructure provisioning |
| **Cloud** | Microsoft Azure | 2024-02 | Cloud platform |
| **Network** | Hub-Spoke VNets | N/A | Network segmentation |
| **Security** | Azure Firewall | Standard | Perimeter defense |
| **SIEM** | Microsoft Sentinel | GA | Threat detection |
| **Logging** | Log Analytics | Standard | Centralized logs |
| **Query** | KQL | Latest | Log analysis language |
| **ML** | scikit-learn | 1.3+ | Anomaly detection |
| **ML Models** | Isolation Forest, RF | N/A | Classification |
| **LLM** | GPT-4o | Latest | AI analysis |
| **Automation** | Logic Apps | GA | SOAR orchestration |
| **Ticketing** | Jira | Cloud | Incident tracking |
| **Attack Tools** | Kali Linux | Latest | Pen testing |

---

**Document Version**: 1.0  
**Last Updated**: February 2026  
**Classification**: Internal Use  
**Status**: Production Ready
