# Cost Optimization Report — Project A.V.A.R.S

## Executive Summary
This report summarizes cost-optimization opportunities for the A.V.A.R.S lab running on Microsoft Azure. The lab includes multiple VMs (scanning and attack VMs), Log Analytics/Sentinel ingestion, storage for scan results, and optional ML training. Without optimizations, a moderate lab can cost several hundred to several thousand dollars per month. Using Azure Advisor recommendations, Reserved Instances (RIs), and operational controls we can reduce ongoing costs substantially.

## Estimated Current Cost (Example)
- Compute (8 × Standard_B4ms VMs): ~$2,400 - $3,200 / month
- Log Analytics ingestion & retention: ~$400 - $1,200 / month (scale-dependent)
- Storage (blobs, SQL db): ~$200 - $800 / month
- Networking & public IPs: ~$50 - $200 / month
- Misc (Azure Monitor, Logic Apps run costs): ~$50 - $500 / month

**Estimated total (unoptimized): $3,100 - $5,900 / month**

## Key Optimization Opportunities

### 1. Reserved Instances / Savings Plans
- Reserve VMs for 1-year or 3-year terms to obtain 30–55% discount for predictable workloads.
- Identify long-running VMs (Sentinel, core services) and convert them to RIs.
- For bursty workloads (ML training), keep on-demand or use spot instances for non-critical workloads.

Estimated savings: 30–40% on long-running compute → ~$700–1,200/month.

### 2. Azure Advisor Recommendations
- Review Advisor to: identify idle VMs, right-size VM SKUs, and remove unattached disks/public IPs.
- Action items:
  - Schedule automatic shutdown/startup for non-production VMs to save costs.
  - Use Advisor recommendations for SQL DB tier adjustments.

Estimated savings: $100–400/month depending on remediation.

### 3. Log Analytics Retention & Sampling
- Reduce retention period for noisy telemetry (e.g., dev/test) or move to cheaper archive tiers.
- Use sampling or pre-filtering rules to reduce ingestion for high-volume logs.
- Use cost alerts and budgets to monitor ingestion volumes.

Estimated savings: $200–800/month depending on retention.

### 4. Spot Instances for Batch/Training Jobs
- Use spot VMs for ephemeral ML training workloads or large scans where interruption is acceptable.
- Persist artifacts to blob storage and resume training using checkpoints.

Estimated savings: 20–70% for training costs when appropriate.

### 5. Storage & Data Lifecycle
- Use lifecycle policies to move old scan results to Cool/Archive tiers.
- Delete or compress old PoC data older than retention policy.

Estimated savings: $50–200/month.

## Action Plan & Checklist
1. Run Azure Advisor and export recommendations.
2. Tag resources for cost reporting (project, owner, environment).
3. Identify candidates for Reserved Instances (core VMs) and purchase 1-year RIs.
4. Implement auto-shutdown for non-critical VMs (nightly schedule).
5. Implement Log Analytics sampling and reduce retention where acceptable.
6. Configure lifecycle policies for scan result containers.
7. Set budgets and alerts in Azure Cost Management.

## Commands & Tools
- View Advisor recommendations (Azure CLI):
```bash
az advisor recommendation list --resource-group <rg>
```
- Query Cost Management (example):
```bash
az costmanagement query --type Usage --timeframe MonthToDate --dataset-configuration '{"granularity":"Daily"}'
```
- Purchase Reserved Instances via portal or CLI (example omitted due to account-specific steps).

## Expected Outcome
- **Target savings:** 30–50% on ongoing lab costs.
- **Example:** reduce $4,000/month → $2,000–2,800/month after optimizations.

## Notes & Risks
- RIs are a commitment; ensure core workloads are stable before purchase.
- Spot instances can be evicted; do not use for critical production processes.
- Monitoring reductions in ingestion/retention may reduce forensic capability—balance cost vs compliance needs.

---
*Prepared for Project A.V.A.R.S — Cloud Security Engineer*