# Case Study: Infrastructure Security - Secure by Design with Terraform

## 2-Minute Interview Script
"A core design goal in A.V.A.R.S was to avoid reactive security by building controls into infrastructure from day one. I used Terraform to define a hub-and-spoke architecture with centralized logging, Sentinel integration, Key Vault for sensitive material, and controlled network boundaries. This secure-by-design approach reduces configuration drift and makes security posture repeatable across environments. It also reflects practical AZ-900 cloud foundations applied in a security engineering context."

## STAR Answer
### Situation
Cloud labs often become inconsistent over time, with manual changes introducing configuration drift and avoidable exposure.

### Task
Create a repeatable, auditable infrastructure baseline that embeds security controls by default.

### Action
- Defined core Azure topology and controls in Terraform.
- Centralized telemetry in Log Analytics and Sentinel.
- Integrated Key Vault for secrets and trust anchors.
- Validated IaC with repeatable checks and deployment guidance.

### Result
- Established a reusable secure baseline for detection and response experiments.
- Reduced manual configuration risk and improved deployment consistency.
- Demonstrated cloud security foundations expected in entry cloud-security roles.

## Situation
Manual cloud setup approaches were high-friction and prone to inconsistent security configuration.

## Task
Implement infrastructure that is secure, reproducible, and operationally supportable.

## Actions
- Applied Terraform-first provisioning model.
- Embedded central monitoring and secret management as default components.
- Added governance-focused documentation and validation workflow.

## Result
- Improved consistency and reduced misconfiguration exposure.
- Made the security architecture easier to review, explain, and maintain.

## Evidence Points to Discuss in Interview
- Why secure-by-design beats bolt-on security.
- How IaC improves repeatability and auditability.
- How centralized telemetry accelerates incident response.

## Competency Mapping
- AZ-900: Core Azure architecture and governance foundations.
- SC-200: SIEM-aligned telemetry architecture readiness.
- Security+: Foundational security architecture principles.
