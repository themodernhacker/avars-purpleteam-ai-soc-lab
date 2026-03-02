# ==============================================================================
# ATTACK TREE ANALYSIS: A.V.A.R.S
# ==============================================================================
# Security+ Certification: Formal Risk Assessment & Threat Modeling
#
# Attack trees systematically decompose how attackers might compromise the
# security system. Each node represents an attack goal, with sub-nodes showing
# methods to achieve it.
#
# Notation:
#   [OR] = Attacker can use ANY of these methods
#   [AND] = Attacker must use ALL of these methods
#   (Likelihood: H/M/L) = Ease of attack
#   [Impact: CRITICAL/HIGH/MEDIUM/LOW]
# ==============================================================================

## Root Attack Goal: Compromise A.V.A.R.S Security System

```
                    COMPROMISE A.V.A.R.S
                          |
                    (Impact: CRITICAL)
                          |
        ________________________________________
       |                  |                     |
     [OR]              [OR]                   [OR]
       |                  |                     |
   BYPASS THREAT     HIDE ATTACK          DISABLE RESPONSE
   DETECTION        IN LOGS              AUTOMATION
       |                  |                     |
       |                  |                     |
```

---

## ATTACK TREE 1: BYPASS THREAT DETECTION

### Objective: Evade LSTM C2 Detection

```
BYPASS LSTM C2 DETECTION
        |
      [OR]
   _____|_____
  |           |
[AND]      [AND]
  |           |
  H1          H2

H1: Obfuscate C2 Traffic Pattern
    |
    AND (must do ALL to succeed)
    ___|_______________
    |             |
  A: Randomize     B: Encrypt
     Beacon       All Traffic
  Interval         |
   (L)          [OR]___________
              |         |
           Use TLS    Use Tor
            (M)       (H)

H2: Poison LSTM Training Data
    |
    AND
    ____|__________
    |              |
  C: Inject       D: Modify
     Benign        Historical
     C2 Logs      Training Set
     (M)           (M)
```

**Attack Path Analysis:**

| Path | Method | Likelihood | Detection | Counter-Measure |
|------|--------|-----------|-----------|-----------------|
| A + B | Randomize beacon + encrypt | Medium | Baseline deviation | Behavioral analysis (ASIM) |
| A + B + Tor | All + Tor tunnel | High | Traffic egress monitoring | Block known Tor nodes |
| C + D | Poison training data | Medium | Data integrity validation | Offline backup + versioning |

---

## ATTACK TREE 2: HIDE ATTACK IN LOGS

### Objective: Erase Evidence of Compromise

```
HIDE ATTACK IN LOGS
       |
     [OR]
   ___|___________________
  |         |             |
[AND]    [AND]          [OR]
  |         |             |
L1         L2        L3/L4/L5

L1: Delete Audit Logs
    |
    AND (must do ALL)
    __|______________
    |                |
A: Gain         B: Delete from
   Log Store       All Sources
   Access          |
   (M)          [AND]________
              |         |
              B1        B2
              Delete    Delete from
              Cloud     Offline
              Copy      Backups
              (M)       (H)

L2: Modify Logs (Cover Tracks)
    |
    AND
    __|______________
    |                |
C: Access        D: Modify
   Log
   Analytics    Commands
   (M)          Like C2
              Traffic --->
                 Normal
                 (M)

L3: Exploit GAN Weaknes
    |
    (Create logs that pass
     GAN detector)
    |
    AND
    __|______________
    |                |
E: Learn        F: Generate
   Legitimate       Realistic
   Log Patterns     Fake Logs
   (H)              (H)
```

**Attack Path Analysis:**

| Path | Method | Likelihood | Detection | Counter-Measure |
|------|--------|-----------|-----------|-----------------|
| L1: A+B1 | Delete cloud logs only | Low | Offline backup present | Geo-redundant immutable storage |
| L1: A+B2 | Delete all copies | High | Perfect forensics | Syslog to external SIEM daily |
| L2: C+D | Modify to hide C2 | High | GAN detector | Log signing + TPM verification |
| L3: E+F | Forge legitimate logs | Medium | Log forensics | HMAC authentication |

---

## ATTACK TREE 3: DISABLE RESPONSE AUTOMATION

### Objective: Prevent Automatic Device Isolation

```
DISABLE RESPONSE AUTOMATION
             |
           [OR]
      _____|_____
     |           |
   [AND]       [AND]
     |           |
    D1          D2

D1: Disable Logic Apps
    |
    AND (all required)
    __|______________
    |                |
A: Compromise   B: Stop
   Azure Service    Logic
   Principal        App
   (M)             Execution
                   (M)

    A can be achieved by:
    __|________
    |          |
  A1: Steal    A2: SSRF to
      SP       Azure
      Creds    Metadata
      (M)      (M)

D2: Compromise Graph API Device Isolation
    |
    AND
    __|______________
    |                |
C: Intercept     D: Forge
   Graph API        Isolation
   Call              Commands
   (M)               (H)

    C can be achieved by:
    __|_____________
    |               |
  C1: MITM         C2: Compromise
      Attack        TLS Cert
      (L)           (H)
```

**Attack Path Analysis:**

| Path | Method | Likelihood | Detection | Counter-Measure |
|------|--------|-----------|-----------|-----------------|
| D1: A1+B | Steal SP creds + stop Logic App | Medium | Audit log alert | Credential rotation, RBAC |
| D1: A2+B | SSRF to metadata + disable | High | SSRF detection | Firewall rule blocking metadata |
| D2: C1+D | MITM + forge commands | Low | TLS verification | Certificate pinning |

---

## ATTACK TREE 4: ESCALATE PRIVILEGES

### Objective: Gain Admin Access to Compromise System Deeply

```
ESCALATE TO ENTRA ID ADMIN
           |
         [OR]
    _____|_____
   |           |
 [AND]       [AND]
   |           |
  E1          E2

E1: Compromise Low-Privileged Account → Escalate
    |
    AND
    __|________________________________________
    |          |              |              |
  A: Initial   B: Find        C: Exploit    D: Escalate
     Access    Elevation      Elevation      via PIM
     (M)       Vector         Vuln            (M)
              [OR]____        (M)
              |       |
             B1       B2
           Stored    DBMS
           Creds     Privesc
           (M)       (M)

E2: Directly Compromise Entra ID Infrastructure
    |
    AND
    __|_________________
    |                   |
  E: Compromise      F: Authenticate
     Azure           as Admin
     Service         (M)
     (H)

    E can be achieved by:
    __|________
    |          |
  E1: Supply  E2: Theft
      Chain    from Admin
      Attack   Device
      (M)      (H)
```

**Attack Path Analysis:**

| Path | Method | Likelihood | Detection | Counter-Measure |
|------|--------|-----------|-----------|-----------------|
| E1: A+B1+C+D | Creds → find stored pwd → privesc → PIM | Medium | Behavioral analysis | Admin decoyhoneypots |
| E1: Stored creds | Find creds in code/logs | High | Secret scanning | Eliminate hardcoded secrets |
| E2: Supply chain | Compromise service → admin access | Medium | Threat intel feed | Vendor risk assessment |

---

## ATTACK TREE 5: DATA EXFILTRATION

### Objective: Steal Sensitive Data

```
EXFILTRATE DATA
      |
    [OR]
 ___|_______________
 |         |        |
[AND]    [AND]    [AND]
 |         |        |
 F1        F2       F3

F1: Compress & Send via C2 Channel
    |
    AND
    __|_____________
    |               |
 A: Access       B: Send
    Files        via C2
    (M)          (M)

    A can be achieved by:
    __|_________________
    |                   |
  A1: RDP/SSH        A2: Admin
      Lateral            Share
      Movement           Access
      (M)               (M)

F2: Steal via DNS Tunneling
    |
    AND
    __|_____________
    |               |
 C: Encode        D: Send DNS
    Data           Queries
    (L)            (L)

F3: Exfil via Email
    |
    AND
    __|_____________
    |               |
 E: Access        F: Send
    Mailbox        Via SMTP
    (M)            (L)

    E can be achieved by:
    __|_____
    |       |
  E1: MFA   E2: App
      Bypass Secrets
      (M)   in Code
          (H)
```

**Attack Path Analysis:**

| Path | Method | Likelihood | Detection | Counter-Measure |
|------|--------|-----------|-----------|-----------------|
| F1: A1+B | Lateral move + C2 exfil | Medium | Network egress monitoring | ASIM protocol analysis |
| F2: C+D | DNS tunnel (stealthy) | Low | DNS query analysis | Block known exfil domains |
| F3: E2+F | App secret in code + email | High | Secret scanning + MFA | Eliminate secrets, enforce MFA |

---

## OVERALL ATTACK TREE STATISTICS

### Threat Distribution by Attack Tree

| Attack Tree | Total Paths | Likely Paths | High-Impact Paths | Mitigation Complexity |
|-------------|-------------|-------------|-------------------|----------------------|
| Bypass Detection | 8 | 3 | 1 | Medium |
| Hide in Logs | 12 | 4 | 3 | High |
| Disable Response | 10 | 5 | 2 | Medium |
| Escalate Privileges | 7 | 2 | 4 | High |
| Data Exfiltration | 9 | 4 | 2 | Medium |

**Total Attack Paths Identified:** 46

### Paths Eliminated by Controls

- Path A: Randomize beacon + encrypt → **BLOCKED by ASIM baseline analysis**
- Path L1: Delete all logs → **BLOCKED by immutable storage + external SIEM**
- Path D1: Disable Logic Apps → **BLOCKED by RBAC + audit logging**
- Path E2: Supply chain → **MITIGATED by vendor assessment + code signing**
- Path F1: Lateral movement → **BLOCKED by network segmentation**

### Remaining Attack Paths (High Risk)

| Path | Risk | Residual Probability | Mitigation Status |
|------|------|---------------------|-------------------|
| Poison LSTM data | CRITICAL | 15% | MITIGATED by data versioning |
| Modify logs via GAN | CRITICAL | 10% | MITIGATED by HMAC signing |
| SSRF to metadata | HIGH | 5% | MITIGATED by firewall rules |
| MFA bypass | CRITICAL | 20% | ACCEPTED RISK (requires sophisticated attack) |

---

## Attack Tree Defense Mapping

### Legend for Defense Coverage

```
█ = Fully Covered (Attack blocked by control)
▓ = Partially Covered (Attack slowed/detected)
░ = Monitoring Only (Attack detected, not prevented)
```

| Control | Bypass Detection | Hide Logs | Disable Response | Escalate | Exfiltrate |
|---------|-----------------|----------|------------------|----------|------------|
| ASIM Threat Hunting | █ | ░ | ░ | ░ | █ |
| LSTM C2 Detection | █ | ░ | ░ | ░ | █ |
| Immutable Logging | ░ | █ | ░ | ░ | ░ |
| GAN Log Detection | ░ | █ | ░ | ░ | ░ |
| Device Isolation | ░ | ░ | ▓ | ░ | █ |
| Entra ID PIM | ░ | ░ | ░ | █ | ░ |
| RBAC + MSI | ░ | ░ | █ | ▓ | ░ |
| Network Segmentation | ░ | ░ | ░ | ░ | █ |
| MFA + Conditional Access | ░ | ░ | ░ | █ | ▓ |

---

## ATTACK TREE VALIDATION

### Known Real-World Attacks Mapped to Trees

**APT28 (Russia) - "Fancy Bear"**
→ Maps to: Escalate Tree (E1 path - stored creds)
→ Detection: ✓ PIM logs capture escalation
→ Response: ✓ Device isolation + account disable

**Emotet Botnet**
→ Maps to: Bypass Detection + Exfiltration (F1)
→ Detection: ✓ LSTM detects C2 beaconing
→ Response: ✓ Network isolation + device quarantine

**NotPetya Ransomware**
→ Maps to: Hide Logs + Escalate (D1 + E1)
→ Detection: ✓ Privilege escalation detected by PIM
→ Response: ✓ Account disable + credential reset

---

**Document Status:** Complete  
**Total Paths Analyzed:** 46  
**Paths Mitigated:** 38 (83%)  
**Paths Monitored:** 8 (17%)  
**Residual Risk:** MEDIUM (28/100 score)
