# Case Study: SOC Incident Response - Stealthy C2 Containment

## 2-Minute Interview Script
"In A.V.A.R.S, I simulated a low-and-slow C2 beacon to reflect realistic adversary behavior rather than noisy attack traffic. Signature and threshold rules were not sufficient early on, so I used an LSTM-based anomaly detector to identify timing irregularities and then integrated that output into Sentinel-driven SOAR. The containment path isolated AKS context and revoked related Entra sessions, with Human-in-the-Loop governance for high-impact decisions. This transformed response from manual triage windows to near-real-time action in my lab and demonstrated how AI plus cloud-native controls can reduce dwell time without sacrificing operational safety."

## STAR Answer
### Situation
A stealthy DNS beacon pattern attempted to maintain command-and-control while staying below standard alert thresholds.

### Task
Detect and contain quickly, while reducing the chance of a business-disruptive false block.

### Action
- Applied LSTM anomaly scoring to flow-sequence behavior.
- Enriched Sentinel incidents with model confidence context.
- Triggered Logic App containment for AKS isolation and session revocation.
- Kept HITL approval for critical response safety.

### Result
- Detected behavior missed by static thresholding.
- Reduced response from manual windows to near-real-time containment in lab paths.
- Improved SOC confidence through auditable, policy-aligned automation.

## Situation
A low-and-slow DNS tunneling pattern attempted to establish command-and-control behavior from a monitored workload. Traditional threshold-based Sentinel rules did not generate early signal due to intentionally sparse traffic.

## Task
Detect and contain the potential C2 channel quickly while minimizing the risk of unnecessary disruption to legitimate business traffic.

## Actions
- Applied sequence-based anomaly scoring using the AVARS LSTM model.
- Triggered Sentinel enrichment with anomaly context and confidence score.
- Executed Logic App containment workflow to isolate AKS context and revoke Entra ID session.
- Preserved Human-in-the-Loop governance for high-impact containment decisions.
- Captured all actions in incident timeline for auditable post-incident review.

## Result
- Detected stealthy behavior that static thresholding missed.
- Reduced MTTR from ~45 minutes to ~12 seconds through SOAR containment.
- Prevented sustained attacker command flow and reduced lateral movement risk.

## Evidence Points to Discuss in Interview
- Why low-and-slow DNS often evades fixed-threshold detections.
- How model confidence was combined with SOC policy for actioning.
- Why HITL control remains critical for operational risk management.

## Competency Mapping
- SC-200: Sentinel analytics, incident handling, automation integration.
- Security+: Detection/response lifecycle and operational control rationale.
- eJPT: Adversary behavior understanding and containment prioritization.
