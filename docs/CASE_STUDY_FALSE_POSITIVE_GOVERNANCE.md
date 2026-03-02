# Case Study: False-Positive Governance - Operational Noise Reduction

## 2-Minute Interview Script
"A key SOC engineering challenge I solved in A.V.A.R.S was alert fatigue from authorized scanner traffic. Instead of weakening detections, I implemented watchlist-driven suppression with Azure CLI automation and whitelist-aware KQL. This ensured approved scanners were filtered while unknown traffic still triggered alerts. I also added CI validation for the automation scripts so rule-governance controls stay consistent over time. The net result was a 98% drop in false positives and materially better analyst focus on real incidents."

## STAR Answer
### Situation
Authorized scanning behavior generated high-volume brute-force-like alerts and reduced SOC effectiveness.

### Task
Reduce alert noise without creating blind spots for real attacks.

### Action
- Deployed Sentinel watchlist `ip_whitelist` with lifecycle fields.
- Implemented KQL suppression referencing watchlist data.
- Automated deployment with Azure CLI scripts and CI checks.
- Kept suppression auditable and reversible through documented governance.

### Result
- Cut false-positive volume by 98%.
- Improved signal-to-noise ratio and triage throughput.
- Preserved detection coverage for concurrent real attack signals.

## Situation
Authorized vulnerability scanning generated scanner-originated traffic that looked like brute-force behavior, creating 500+ false-positive alerts and reducing analyst efficiency.

## Task
Lower false-positive volume without weakening detection coverage for genuine malicious activity.

## Actions
- Implemented Sentinel watchlist `ip_whitelist` for approved scanner/source IPs.
- Added whitelist-aware KQL filtering in detection queries.
- Automated watchlist + scheduled-rule deployment with Azure CLI scripts.
- Added CI checks to validate PowerShell and Bash automation scripts.
- Documented watchlist governance fields (owner, reason, expiry) for safe suppression.

## Result
- Reduced false-positive alert volume by ~98%.
- Restored SOC analyst focus to true-positive investigations.
- Improved signal-to-noise ratio and triage quality in operational workflow.

## Evidence Points to Discuss in Interview
- How watchlists should be governed to avoid permanent blind spots.
- Why suppression logic must be auditable and reversible.
- How automation supports repeatability across environments.

## Competency Mapping
- SC-200: Analytics tuning, watchlists, SOC operations.
- Security+: Incident management and operational process control.
- AZ-900/SC-400: Cloud-native service use and data handling governance.
