# Case Study 02: Operational Noise Reduction

## Executive Summary
A sanctioned vulnerability scanner generated heavy authentication-style traffic and triggered 500+ false-positive brute-force alerts. AVARS introduced watchlist-based suppression using CLI automation and KQL filtering, cutting alert volume by 98% and allowing analysts to focus on true threats.

## 1) The 2-Minute Interview Script
"One of the most practical SOC challenges I solved in A.V.A.R.S was alert fatigue. Authorized vulnerability scanners were generating hundreds of false-positive brute-force alerts in Sentinel. Instead of disabling detections, I implemented a dynamic watchlist pattern through Azure CLI automation and updated KQL to apply suppression safely. In practice, this used watchlist-aware filtering so authorized scanner IPs were excluded while unknown sources still generated incidents. This aligns closely with SC-200 operations: tuning analytics for fidelity, preserving coverage, and ensuring the SOC focuses on high-confidence signals. The result was a 98% reduction in noise and better visibility of real attack activity, including SQL injection signals that would otherwise have been buried." 

## 2) STAR Method Answer
### Situation
The SIEM environment experienced alert fatigue, with the majority of brute-force incidents triggered by internal authorized vulnerability scanning.

### Task
Tune analytics to suppress authorized traffic while maintaining a strict detection posture for unauthorized external attempts.

### Action
- Built non-interactive deployment automation for Sentinel watchlist management via Azure CLI.
- Added whitelist-aware KQL logic to cross-reference failed-logon source IPs.
- Added script quality gates in GitHub Actions to prevent drift in automation behavior.
- Documented governance controls (owner, reason, expiry) to prevent permanent blind spots.

### Result
- Reduced false-positive alert volume by 98%.
- Improved SOC signal-to-noise ratio and triage speed.
- Enabled analysts to catch a real concurrent SQL injection scenario that previously could be buried in noise.

## Scenario
- Trigger: Scheduled internal scanner and sanctioned testing workloads
- Problem: Brute-force style detections overwhelmed SOC queue
- Risk: Analyst fatigue and delayed response to true-positive incidents

## Root Cause
- Detection logic lacked dynamic allowlisting for approved scanner IPs
- Operational context (authorized infrastructure) not encoded in analytics path

## Remediation Implemented
1. Created Sentinel watchlist alias `ip_whitelist`
2. Imported approved IPs from CSV using non-interactive CLI script
3. Updated KQL logic to exclude watchlisted entities
4. Added automation scripts for repeatable governance (`.ps1` and `.sh`)
5. Added CI checks to validate automation scripts on push/PR

## Outcome
- Alert reduction: ~500+ noisy alerts reduced by 98%
- SOC efficiency: Queue quality improved; analysts prioritized real SQLi attempt
- Process maturity: Repeatable false-positive governance with documented controls

## Security Value
- Better signal-to-noise ratio in Sentinel analytics
- Lower analyst burnout risk
- More defensible incident response metrics and triage quality

## Interview Talking Points
- How operational context prevents alert fatigue
- Why watchlist governance should include owner and expiry fields
- How to balance suppression with detection coverage
- How this demonstrates practical SC-200 + SOC engineering capability

## Resume Bullet
Engineered Sentinel false-positive governance by deploying watchlist-driven KQL suppression and CLI automation, reducing alert noise by 98% and improving analyst focus on confirmed attack activity.
