# Project A.V.A.R.S
## AI-Verified Automated Response System

A comprehensive cloud-based cybersecurity lab demonstrating enterprise-grade threat detection, AI-driven incident analysis, and automated response capabilities.

## Open-Source Status (March 2026)
- ✅ MIT licensed and ready to clone
- ✅ Local validation pipeline passes (`scripts/run_all_checks.ps1 -IncludeRiskRun`)
- ✅ Terraform root module validates successfully
- ℹ️ Full cloud behavior (Sentinel incidents, Logic Apps, OpenAI, live attacks) requires an Azure subscription with supported quotas

For a clean clone-to-first-run path, use this guide: `docs/DEPLOYMENT.md`.

### 📊 Project Impact
- **Demonstrates DevSecOps excellence** through Infrastructure as Code
- **Combines offensive & defensive** security operations
- **Leverages real ML/AI** for threat detection and analysis (not just prompts)
- **Automates incident response** with SOAR capabilities
- **Production-ready architecture** on Microsoft Azure

---

## 🏗️ Architecture Overview

### Phase 1: Cloud Fabric (Infrastructure as Code)
**Technology:** Terraform  
**Architecture Pattern:** Hub-and-Spoke

```
┌─────────────────────────────────────────────┐
│         Azure Hub (Security Core)            │
│  ├─ Azure Firewall                          │
│  ├─ Log Analytics Workspace                 │
│  ├─ Microsoft Sentinel                      │
│  └─ Key Vault (Secrets Management)          │
└─────────────────────────────────────────────┘
              ↓                ↓
    ┌──────────────┐  ┌──────────────┐
    │ Spoke 1      │  │ Spoke 2      │
    │ Honey-Net    │  │ Management   │
    ├─ ACI         │  ├─ Kali Linux  │
    │ (OWASP JuiceShop)  │ (Attack VM)    │
    │ (SSH Honeypot)     │              │
    └──────────────┘  └──────────────┘
```

### Phase 2: Attack & Ingestion (Detection Layer)
**Technology:** Azure Monitor Agent, KQL, MITRE ATT&CK  
**Attacks:** Credential Stuffing, SQL Injection  
**Detection:** Real-time log streaming with MITRE mapping

### Phase 3: MSc "X-Factor" (AI/ML Integration)
**Generative AI:** Azure OpenAI (GPT-4o) for incident analysis  
**Predictive AI:** Random Forest/Isolation Forest for anomaly detection  
**Deployment:** Azure ML, Azure Logic Apps

### Phase 4: Automated Kill-Switch (SOAR)
**Technology:** Azure Logic Apps  
**Capabilities:**
- Human-in-the-Loop (HITL) approval before critical firewall block (Approve/Ignore)
- Firewall IP blocking
- Container isolation
- Automated Jira/GitHub issue creation
- Executive summaries via AI

---
## 🚀 Quick Start

### LEGAL & SAFE USE NOTICE
This project includes offensive security tooling and simulated exploitation code for testing in authorized environments only. Do **not** run penetration or C2 simulation scripts against systems you do not own or do not have explicit written permission to test. The authors and maintainers are not responsible for misuse. Obtain explicit authorization and follow your organisation's rules of engagement.

### Prerequisites
- Azure Subscription (with credits)
- Terraform (>= 1.0) installed locally
- Azure CLI configured and logged in
- Git
- Python 3.10+ and `pip`
- SSH keys for Linux VM provisioning (for OpenVAS/Metasploit)

### Clone & Validate (recommended first run)
```bash
git clone <your-repo-url>
cd "Project A.V.A.R.S"
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run_all_checks.ps1 -Quick
```

For full local validation (includes script smoke tests and risk quantification):
```bash
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run_all_checks.ps1 -IncludeRiskRun
```

GitHub Actions in this repository are configured so deploy jobs are **opt-in only** via manual workflow dispatch input (`run_deploy=true`).

### 5-Minute Starter Path
1. Run the quick validation command above.
2. Copy `terraform/terraform.tfvars.example` to `terraform/terraform.tfvars` and add your Azure subscription/tenant IDs.
3. Run `terraform init` and `terraform plan -var-file="terraform.tfvars"` from `terraform/`.
4. Follow browser-first deployment phases in `docs/DEPLOYMENT.md`.

### Deployment - High level, per-component commands
Note: these are example commands; adjust `terraform/*.tfvars` and environment variables as needed.

1) Deploy core infrastructure (Hub & Spokes, Sentinel, Key Vault):
```bash
cd terraform
terraform init
terraform plan -out=tfplan -var-file="terraform.tfvars"
terraform apply tfplan
```

2) Provision vulnerability scanning & red-team VMs (Nessus, OpenVAS, Metasploit, Burp):
```bash
# Reintegrated provider-compatible vulnerability module
cd terraform
terraform apply -target=azurerm_storage_account.vuln_scan_reports[0] -var-file="terraform.tfvars"
```

3) Python tooling (pen-testing automation, exploit PoC, risk quant):
```bash
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1    # Windows PowerShell
source .venv/bin/activate # Linux/macOS
pip install -r ml-notebooks/requirements.txt
python scripts/penetration-test-automation.py --target http://<test-target> --all
python scripts/exploit-poc-c2.py --scenario full --duration 300
python scripts/risk-quantification.py --report outputs/risk_report.json
```

4) Train ML models (transformer, DQN, GAN) locally or on Azure ML:
```bash
python ml-notebooks/transformer-nlp-threat-hunting.py
python ml-notebooks/reinforcement-learning-adaptive-defense.py
python ml-notebooks/gan-detection-spoofed-logs.py
```

5) Deploy Logic Apps (SOAR) and link to Sentinel:
```bash
# Use Azure CLI or the `logic-apps` ARM/JSON templates in the repo
az login
az deployment group create --resource-group <rg> --template-file logic-apps/incident_response_workflow.json
```

---

## 📁 Project Structure

```
Project A.V.A.R.S/
├── terraform/              # Phase 1: IaC
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── network.tf
│   ├── honeypot.tf
│   ├── monitoring.tf
│   ├── vulnerability-scanning.tf
│   ├── physical-security-system.tf
│   ├── aks.tf
│   ├── defender-for-cloud-cspm.tf
│   ├── defender-for-endpoint-mde.tf
│   └── entra-id-pim.tf
├── scripts/
│   ├── attacks/            # Phase 2: Attack scripts
│   │   ├── credential_stuffing.py
│   │   └── sql_injection.py
│   ├── penetration-test-automation.py       # Automated pentest framework
│   ├── exploit-poc-c2.py                    # C2 simulation & PoCs
│   ├── risk-quantification.py               # ALE / Monte Carlo / sensitivity
│   └── kql/                # Phase 2: Detection queries
│       ├── mitre_mapping.kql
│       ├── false_positive_whitelist.kql
│       ├── ip_whitelist_watchlist.csv
│       ├── false_positive_whitelist_analytics_rule.md
│       ├── deploy_sentinel_whitelist_controls.ps1
│       └── deploy_sentinel_whitelist_controls.sh
├── ml-notebooks/           # Phase 3: ML models
│   ├── anomaly_detection.ipynb
│   ├── transformer-nlp-threat-hunting.py
│   ├── reinforcement-learning-adaptive-defense.py
│   └── gan-detection-spoofed-logs.py
├── logic-apps/             # Phase 4: Automation
│   ├── incident_response_workflow.json
│   ├── defender-cloud-remediation.json
│   ├── incident-response-with-lstm-identity.json
│   └── lstm-to-endpoint-isolation.json
├── config/                 # Configuration files
│   └── variables.env
├── docs/                   # Documentation
│   ├── ARCHITECTURE.md
│   ├── DEPLOYMENT.md
│   ├── THREAT_MODEL_STRIDE_DFD.md
│   ├── ATTACK_TREE_ANALYSIS.md
│   ├── PROJECT_COMPLETION_SUMMARY.md
│   ├── CASE_STUDY_SOC_INCIDENT_STEALTHY_C2_CONTAINMENT.md
│   ├── CASE_STUDY_FALSE_POSITIVE_GOVERNANCE.md
│   ├── CASE_STUDY_AI_INTEGRITY_ASSURANCE.md
│   ├── CASE_STUDY_QUANTITATIVE_RISK_BOARD_COMMUNICATION.md
│   └── CASE_STUDY_INFRASTRUCTURE_SECURITY_SECURE_BY_DESIGN.md
├── Case_Studies/            # Interview-ready scenario narratives
│   ├── 01_The_Stealthy_C2_Containment.md
│   └── 02_Operational_Noise_Reduction.md
├── README.md
```

---

## 🎯 Key Technologies

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Infrastructure** | Terraform | IaC for reproducibility |
| **Cloud Platform** | Microsoft Azure | Enterprise cloud |
| **Honeypot** | OWASP Juice Shop | Web vulnerability |
| **Honeypot** | SSH Honeypot | Brute force detection |
| **Monitoring** | Azure Monitor Agent | Log collection |
| **SIEM** | Microsoft Sentinel | Alert management |
| **False Positive Control** | Sentinel Watchlists | Whitelist known-safe IPs |
| **Querying** | KQL (Kusto Query Lang) | Log analysis |
| **Generative AI** | Azure OpenAI (GPT-4o) | Incident summaries |
| **Predictive AI** | Random Forest/Isolation Forest | Anomaly detection |
| **ML Platform** | Azure ML | Model hosting |
| **Automation** | Azure Logic Apps | SOAR/Orchestration |

---

## 🔐 Security Features

✅ **Defense-in-Depth**: Multiple security layers  
✅ **Log Centralization**: All events streamed to Sentinel  
✅ **Real-time Alerting**: Automated incident detection  
✅ **AI-Driven Analysis**: Professional incident reports  
✅ **Human-in-the-Loop Control**: Critical actions require analyst approve/ignore decision  
✅ **Automated Response**: Firewall + container isolation  
✅ **False Positive Suppression**: Sentinel watchlist-backed KQL filtering  
✅ **Audit Trail**: Full compliance logging  
✅ **Log Integrity**: Key Vault stores gold-standard hash references for GAN validation  
✅ **MITRE Framework**: Industry-standard attack mapping  

---

## 📈 Learning Outcomes

After completing this project, you will have demonstrated:

1. ✅ **DevSecOps Engineering**: Infrastructure as Code best practices
2. ✅ **Cloud Security Architecture**: Azure hub-and-spoke design
3. ✅ **Offensive Security**: Real attack execution (eJPT/Sec+ level)
4. ✅ **Defensive Operations**: SIEM configuration and tuning
5. ✅ **KQL Expertise**: Complex log queries with MITRE mapping
6. ✅ **Generative AI Integration**: LLM-driven incident analysis
7. ✅ **Predictive ML**: Anomaly detection on real security data
8. ✅ **SOAR Automation**: Logic-based incident response

---

## 🛠️ Development Status

- [x] Phase 1: Infrastructure Deployment (Terraform manifests present)
- [x] Phase 2: Attack Execution & Detection (attack scripts, scanners)
- [x] Phase 3: ML/AI Integration (transformer, RL, GAN notebooks/scripts)
- [x] Phase 4: Automated Response (Logic Apps + SOAR playbooks)
- [x] Documentation & Case Studies (core docs + interview case studies present)

---

## 📞 Support & Notes

- **Azure CLI**: Used for advanced configurations
- **Terraform State**: Stored locally (consider Azure backend for production)
- **Costs**: ~$50-100/month depending on resource usage
- **Time to Deploy**: ~30 minutes with pre-built scripts

### Maintenance & Operational Notes
- **Terraform state:** Use an Azure Storage backend for shared state and locking in production: consider `azurerm` backend.
- **Secrets:** Store API keys, admin passwords, and certificates in `Key Vault`; do not commit secrets to Git.
- **HITL governance:** For critical alerts, keep Logic App approval in place so analysts explicitly choose Block or Ignore before containment.
- **False positives:** Maintain a Sentinel watchlist (for example `ip_whitelist`) and reference it in KQL to suppress known-safe infrastructure.
- **Log integrity:** Store gold-standard log hash values or signed hash manifests in Key Vault and compare against pipeline outputs before ML scoring.
- **CI quality gate:** GitHub Actions validates PowerShell and Bash Sentinel automation scripts on push/PR (`.github/workflows/validate-automation-scripts.yml`).
- **One-command local validation:** Run `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run_all_checks.ps1 -IncludeRiskRun` to generate a timestamped report under `reports/`.
- **Quick local validation:** Run `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run_all_checks.ps1 -Quick` for fast pre-commit checks.
- **Cost:** The demo lab includes multiple VMs and Log Analytics ingestion which can increase costs; enable Azure Advisor recommendations and consider Reserved Instances for long-running VMs.
- **Backups & DR:** Critical resources should use geo-redundant storage (RA-GRS) and SQL geo-replication if you require failover.
- **Terraform status:** Full root module validates successfully (`terraform validate`) with all modules reintegrated.

---

## 📚 Interview Case Studies

- **Option 2 (scenario-first narratives in `/Case_Studies`)**
    - `Case_Studies/01_The_Stealthy_C2_Containment.md`
    - `Case_Studies/02_Operational_Noise_Reduction.md`
- **Option 1 (formal interview-ready docs in `/docs`)**
    - `docs/CASE_STUDY_SOC_INCIDENT_STEALTHY_C2_CONTAINMENT.md`
    - `docs/CASE_STUDY_FALSE_POSITIVE_GOVERNANCE.md`
    - `docs/CASE_STUDY_AI_INTEGRITY_ASSURANCE.md`
    - `docs/CASE_STUDY_QUANTITATIVE_RISK_BOARD_COMMUNICATION.md`
    - `docs/CASE_STUDY_INFRASTRUCTURE_SECURITY_SECURE_BY_DESIGN.md`

## Where to start

- **If you want SOC/Blue path:** Start with `terraform` to deploy Sentinel and Log Analytics, import `scripts/kql/ip_whitelist_watchlist.csv` as the `ip_whitelist` watchlist, then use `scripts/kql/false_positive_whitelist_analytics_rule.md` + `scripts/kql/false_positive_whitelist.kql` to create a whitelist-aware analytics rule. Follow with `scripts/risk-quantification.py`, optional transformer training, and enable Logic Apps playbooks with HITL approvals.

```powershell
pwsh -File scripts/kql/deploy_sentinel_whitelist_controls.ps1 -ResourceGroupName <rg> -WorkspaceName <sentinel-workspace> -SubscriptionId <subscription-id>
```

```bash
bash scripts/kql/deploy_sentinel_whitelist_controls.sh --resource-group <rg> --workspace-name <sentinel-workspace> --subscription-id <subscription-id>
```
- **If you want Red Team path:** Run `scripts/penetration-test-automation.py` against a sanctioned test target and optionally run `scripts/exploit-poc-c2.py` in an isolated lab only. Deploy IaC red-team telemetry from `terraform/vulnerability-scanning.tf`.

---

## Contributing, License & Contact

- **Contributing:** Please read `CONTRIBUTING.md` (additions welcome). Open issues for bugs or suggested improvements.
- **License:** MIT license is included in `LICENSE`.
- **Contact:** Maintainer: Cloud Security Engineer — open an issue or email `security@example.com` for questions.

---

**Project Version:** 1.0  
**Last Updated:** February 2026  
**Author:** Abhishek Kumar Sahu
