# Case Study 01: The Stealthy C2 Containment

## Executive Summary
A low-and-slow DNS tunneling pattern bypassed standard threshold-based Sentinel detections. The AVARS LSTM anomaly model flagged the behavior with up to 96% confidence in lab testing, triggering an automated response workflow. The workflow isolated the affected AKS workload and revoked the related Entra ID session, reducing response time from manual minutes to seconds.

## 1) The 2-Minute Interview Script
"I’d like to highlight a scenario in my A.V.A.R.S project where I bridged offensive testing and AI-driven defense. I used my eJPT-style attack simulation skills to emulate a low-and-slow C2 beacon designed to evade basic detection thresholds. Standard SIEM rules missed the early pattern, but I developed an LSTM-based detector, informed by my MSc Cybersecurity and AI work, that flagged the traffic with up to 96% confidence based on timing anomalies. I then integrated that signal with Sentinel and a Logic App playbook to contain the threat by isolating the AKS workload and revoking the associated Entra ID session. In practical terms, this reduced response from typical manual triage windows to near-real-time containment in under 15 seconds in the lab, showing how AI can materially reduce attacker dwell time when combined with SOC controls and auditability." 

## 2) STAR Method Answer
### Situation
In my cloud-native lab, I simulated an APT-like scenario where an attacker established a C2 channel using encrypted, randomized heartbeat behavior to avoid signature-based detection.

### Task
My objective was to detect this low-visibility traffic and contain it automatically without causing full service disruption, aligned to SC-200 incident response practices.

### Action
- Implemented a two-tier detection and response approach.
- Built an LSTM model in Python/TensorFlow to score traffic-sequence anomalies.
- Integrated model output with Microsoft Sentinel and Logic App automation.
- Enforced Human-in-the-Loop approval for high-impact containment actions.
- Triggered containment path: isolate AKS context and revoke Entra ID session.

### Result
- Achieved up to 96% detection confidence for stealth beacon behavior in simulated runs.
- Reduced MTTR by roughly 90% (for example, ~30 minutes manual to <15 seconds automated in lab execution paths).
- Supported risk reduction narrative with simulated ALE analysis (including a modeled scenario around £8.2M potential annualized loss exposure).

## Scenario
- Attack type: DNS-based command-and-control (C2) beaconing and covert exfiltration setup
- Threat behavior: Low-frequency, jittered DNS requests designed to avoid noisy signatures
- Initial detection challenge: Traditional analytics rules did not cross alert thresholds

## Detection Path
- Telemetry source: AzureDiagnostics and Sentinel-linked logs
- Detection engine: LSTM anomaly model (sequence behavior scoring)
- Signal quality: up to 96% anomaly confidence based on cadence and entropy drift in lab tests
- Corroboration: Destination reputation and unusual workload DNS profile

## Triage Decision
- Incident classified as high-confidence suspicious C2 behavior
- Human-in-the-Loop control kept for containment confirmation in critical path
- Escalation policy invoked due to model score and blast-radius risk

## Response Workflow
1. Sentinel incident created and enriched with model score
2. Logic App orchestration executed containment chain
3. AKS pod/network context isolated
4. Entra ID session revoked for active principal
5. SOC notified with decision and evidence trail

## Outcome
- Primary impact: C2 channel disrupted before sustained command execution
- Business impact: Reduced risk of lateral movement and staged exfiltration
- MTTR improvement: from manual triage windows to near-real-time containment (for example, ~30 minutes to <15 seconds in lab scenarios)

## Interview Talking Points
- Why baseline rules missed it and why sequence-modeling caught it
- How HITL governance reduced operational risk of over-blocking
- How SOAR reduced MTTR while preserving auditability
- How this maps to SC-200 incident response and SIEM operations

## Resume Bullet
Designed and operated an LSTM-assisted Sentinel + Logic App containment workflow that detected low-and-slow DNS C2 behavior with up to 96% confidence and reduced simulated MTTR to sub-15-second containment through AKS isolation and Entra session revocation.
