# Case Study: AI Integrity Assurance - Trusted Telemetry for Detection Models

## 2-Minute Interview Script
"Because A.V.A.R.S uses GAN/LSTM-assisted detection, I treated telemetry integrity as a first-class security control. My focus was preventing the SOC from making confident decisions on poisoned or tampered logs. I implemented a trust-anchor pattern using gold-standard hash references stored in Key Vault and integrated this into the operational guidance before high-impact automation decisions. This made the AI pipeline more defensible from a governance and audit perspective and showed how I connect AI engineering with practical cloud security controls."

## STAR Answer
### Situation
AI-assisted detections were only as reliable as the underlying telemetry, creating risk if logs were spoofed or altered.

### Task
Add practical controls to strengthen trust in model inputs before high-confidence response actions.

### Action
- Defined a gold-standard hash reference process for critical telemetry artifacts.
- Stored hash manifests in Key Vault as trust anchors.
- Added guidance for hash comparison before high-impact automated decisions.
- Mapped integrity controls to SOC governance and incident evidence practice.

### Result
- Increased confidence in model-assisted detections.
- Lowered risk of acting on tampered telemetry.
- Improved alignment between AI operations and SC-200/SC-400 governance expectations.

## Situation
The project uses GAN/LSTM-assisted analytics for threat detection. Model reliability depends on trustworthy telemetry, but spoofed or tampered logs can degrade accuracy and create unsafe automation outcomes.

## Task
Establish a practical integrity-control pattern to ensure model decisions rely on trusted data.

## Actions
- Defined a gold-standard hash reference workflow for critical telemetry artifacts.
- Stored trusted hash manifests in Azure Key Vault.
- Added operational guidance to compare incoming/log-derived artifacts against trusted references before high-confidence automation.
- Connected integrity controls to incident documentation and governance steps.

## Result
- Improved confidence in model-assisted detections.
- Reduced risk of acting on poisoned/tampered telemetry.
- Strengthened alignment between AI use and cloud security governance practices.

## Evidence Points to Discuss in Interview
- Why AI detection quality is bounded by data integrity.
- How Key Vault improves secret and trust-anchor management.
- How this bridges SC-900/SC-400 governance expectations with practical SOC operations.

## Competency Mapping
- SC-400: Information protection and governance mindset.
- SC-200: Reliable detection engineering in SIEM workflows.
- MSc Cybersecurity + AI: Applied model assurance and operational controls.
