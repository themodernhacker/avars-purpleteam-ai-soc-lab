# 🎓 SC-200 Advanced Threat Hunting with ASIM

## Microsoft Security Engineer Expert Certification Guide  
## Project A.V.A.R.S Implementation

This guide demonstrates **SC-200 level** expertise in:
- Advanced KQL query authoring
- ASIM (Advanced Security Information Model) parsing
- Vendor-agnostic threat hunting
- Multi-stage attack detection
- Forensic analysis in Microsoft Sentinel

---

## Table of Contents

1. [ASIM Architecture](#asim-architecture)
2. [SC-200 Exam Objectives](#sc-200-exam-objectives)
3. [Threat Hunting Patterns](#threat-hunting-patterns)
4. [Advanced Queries](#advanced-queries)
5. [Incident Response Workflows](#incident-response-workflows)
6. [Study Tips for SC-200](#study-tips-for-sc-200)

---

## ASIM Architecture

### What is ASIM?

ASIM = **Advanced Security Information Model**

It's a **normalization schema** that converts logs from different vendors into a standard format.

```
Before ASIM (Vendor-Specific):
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ Palo Alto Logs  │  │  Cisco ASA Logs │  │ Azure FW Logs   │
│  (5 queries)    │  │  (5 queries)    │  │ (5 queries)     │
└────────┬────────┘  └────────┬────────┘  └────────┬────────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              │
                          (15 queries!)

After ASIM (Normalized):
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ Palo Alto Logs  │  │  Cisco ASA Logs │  │ Azure FW Logs   │
└────────┬────────┘  └────────┬────────┘  └────────┬────────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              │
                      _Im_NetworkSession
                       (1 unified query!)
```

### ASIM Key Concepts

#### 1. Filtering vs Parsing
```kql
// ❌ Old way (vendor-specific filter)
CommonSecurityLog
| where DeviceProduct == "PAN-OS"
| where DestinationPort == 443
| where Action == "Deny"

// ✅ ASIM way (vendor-agnostic filter)
_Im_NetworkSession
| where DstPortNumber == 443
| where EventAction == "Drop"
// Works with ANY vendor!
```

#### 2. Normalization in Action
```kql
// Different sources, same unified output:

// From Palo Alto:
//   - src_ip, dst_ip, src_port, dst_port
// From Cisco:
//   - SourceAddress, DestinationAddress, SrcPort, DstPort
// From Azure Firewall:
//   - SourceIP, DestinationIP, SourcePort, DestinationPort
//
// ASIM parser converts all to:
//   - SrcIpAddr, DstIpAddr, SrcPortNumber, DstPortNumber
//
// Result: One query detects across all vendors!
```

#### 3. Schema Consistency
```
ASIM Network Session Schema (_Im_NetworkSession):
├─ EventType           (NetworkSession, NetworkSessionEnd)
├─ EventAction         (Allow, Drop, Deny, Reset)
├─ EventStartTime      (ISO8601)
├─ EventEndTime        (ISO8601)
├─ SrcIpAddr           (10.0.1.5)
├─ DstIpAddr           (203.0.113.45)
├─ SrcPortNumber       (54321)
├─ DstPortNumber       (443)
├─ IpProtocol          (TCP, UDP, ICMP)
├─ EventVendor         (Microsoft, Paloaltonetworks, Cisco, AWS)
├─ EventProduct        (Azure Firewall, PAN-OS, ASA, VPC Flow)
└─ RiskScore_Network   (0-100 custom field)

ASIM Web Session Schema (_Im_WebSession):
├─ EventType           (WebSessionEnd)
├─ EventAction         (Allowed, Blocked)
├─ Url                 (https://example.com/path)
├─ HttpRequestMethod   (POST, GET, PUT, DELETE)
├─ HttpStatusCode      (200, 403, 500)
├─ HttpUserAgent       (Mozilla/5.0...)
├─ SrcIpAddr           (10.0.1.5)
├─ DstIpAddr           (203.0.113.45)
└─ RiskScore_Web       (0-100 custom field)

ASIM Process Creation Schema (_Im_ProcessCreate):
├─ EventType           (ProcessCreate)
├─ ProcessName         (cmd.exe, powershell.exe)
├─ CommandLine         (powershell -nop -enc ...)
├─ ParentProcess       (explorer.exe)
├─ TargetUsername      (domain\user)
├─ TargetUserType      (User, System, Machine)
└─ RiskScore_Process   (0-100 custom field)
```

---

## SC-200 Exam Objectives

### Official Exam Topics Covered by A.V.A.R.S

| Skill Area | SC-200 Requirement | A.V.A.R.S Implementation |
|-----------|-------------------|----------------------|
| **Manage Microsoft Sentinel** | Configure data connectors, logs, and data normalization | Defender for Cloud, MDE, Azure Firewall connectors |
| **Perform Threat Hunting** | Write advanced KQL queries | ASIM parsers for network, web, process threats |
| **Understand ASIM** | Normalize logs across vendors | _Im_NetworkSession, _Im_WebSession, _Im_ProcessCreate |
| **Detect Advanced Threats** | Multi-stage attack patterns | C2 detection, lateral movement, data exfiltration |
| **Investigate Incidents** | Root cause analysis | Forensic timeline reconstruction |
| **Respond to Alerts** | Automated remediation | Logic Apps + Graph API device isolation |
| **Compliance Mapping** | Link incidents to regulatory controls | NIST SP 800-53, ISO 27001 |
| **Performance Tuning** | Optimize analytics rules | Query tuning, alert suppression |

---

## Threat Hunting Patterns

### Pattern 1: C2 Heartbeat Detection (LSTM + ASIM)

**Attack Goal**: Establish persistent command & control

**Detection Logic**:
```kql
_Im_NetworkSession
| where
    // 1. Suspicious destination (known C2 IP)
    (
        DstIpAddr in (dynamic(["203.0.113.45", "203.0.113.46", "203.0.113.47"]))  // Known C2
        or
        // 2. OR: Suspicious port pattern (HTTP/HTTPS to unusual destination)
        DstPortNumber in (80, 443, 8080, 8443)
    )
| where
    // 3. Long-lived connection (beaconing pattern)
    tolong((EventEndTime - EventStartTime) / 1000) > 30  // >30 seconds
| where
    // 4. Regular traffic pattern (every 5 min, like clockwork)
    // Detected by LSTM model trend analysis
    EventVendor == "LSTM_C2_Detector"
    and toreal(RiskScore_Network) >= 0.80  // High confidence
| project
    EventStartTime,
    SrcIpAddr,
    DstIpAddr,
    DstPortNumber,
    tolong((EventEndTime - EventStartTime) / 1000) as DurationSeconds,
    RiskScore_Network,
    EventVendor
| sort by RiskScore_Network desc
```

**SC-200 Concept**: Multi-factor detection (destination + duration + pattern)

---

### Pattern 2: Lateral Movement Detection

**Attack Goal**: Move from compromised VM A to privileged VM B

**Detection via ASIM**:
```kql
// Attack pattern we're looking for:
// 1. Internal source → Internal destination
// 2. Port 445 (SMB - file sharing)
// 3. NEW connection pattern (not normal baseline)

_Im_NetworkSession
| extend
    SrcInternal = ipv4_is_in_range(SrcIpAddr, "10.0.0.0/8") or ipv4_is_in_range(SrcIpAddr, "172.16.0.0/12"),
    DstInternal = ipv4_is_in_range(DstIpAddr, "10.0.0.0/8") or ipv4_is_in_range(DstIpAddr, "172.16.0.0/12")
| where
    SrcInternal and DstInternal                    // Both internal
    and DstPortNumber in (445, 139, 22, 5985)     // SMB, NetBIOS, SSH, WinRM
| where
    RiskScore_Network >= 90                        // High risk port + internal
| join kind=leftanti (
    // Remove established baseline (normal backup traffic)
    _Im_NetworkSession
    | where EventAction == "Allow"
    | where DstPortNumber == 445
    | where TimeGenerated > ago(30d)
    | summarize Count = count() by SrcIpAddr, DstIpAddr
    | where Count > 10  // Normal traffic has high frequency
) on SrcIpAddr, DstIpAddr
| project
    EventStartTime,
    SrcIpAddr,
    DstIpAddr,
    DstPortNumber,
    EventAction,
    RiskScore_Network,
    "LATERAL_MOVEMENT" as AttackType
```

**SC-200 Concept**: Baseline deviation + MITRE ATT&CK mapping

---

### Pattern 3: Data Exfiltration Detection

**Attack Goal**: Copy sensitive data to external IP

**Detection**:
```kql
_Im_NetworkSession
| where
    // 1. Source is internal
    ipv4_is_in_range(SrcIpAddr, "10.0.0.0/8") or ipv4_is_in_range(SrcIpAddr, "172.16.0.0/12")
| where
    // 2. Destination is external
    not (ipv4_is_in_range(DstIpAddr, "10.0.0.0/8") or ipv4_is_in_range(DstIpAddr, "172.16.0.0/12"))
| where
    // 3. Large data transfer (exfiltration signature)
    // Estimate: SentBytes / DurationSeconds
    (dynamic_cast(NumBytes, long, -1) / max(tolong((EventEndTime - EventStartTime) / 1000), 1)) > 1000000  // >1MB/sec
| where
    // 4. Not normal (not a known CDN or cloud service)
    not (DstIpAddr in (dynamic(["8.8.8.8", "1.1.1.1", "93.184.216.34"])))  // Not Akamai, CloudFlare, etc.
| where
    // 5. After hours (anomaly)
    (datetime_diff("hour", EventStartTime, now()) % 24) not in (9, 10, 11, 12, 13, 14, 15)  // Not business hours
| project
    EventStartTime,
    SrcIpAddr,
    DstIpAddr,
    DstPortNumber,
    NumBytes,
    (dynamic_cast(NumBytes, long, -1) / max(tolong((EventEndTime - EventStartTime) / 1000), 1)) as BytesPerSecond,
    "DATA_EXFILTRATION" as AttackType,
    RiskScore_Network
```

**SC-200 Concept**: Multi-factor anomaly detection (size + direction + time)

---

### Pattern 4: Impossible Travel Detection

**Attack Goal**: Indicate account compromise (same user in 2 countries in 30 min)

**Detection - SC-200 Level**:
```kql
let MaxMilesPerHour = 500;  // Max speed (airplane)

_Im_NetworkSession
| extend
    Country = geo_ip_to_country(SrcIpAddr),
    Latitude = geo_ip_to_latitude(SrcIpAddr),
    Longitude = geo_ip_to_longitude(SrcIpAddr),
    Timestamp = EventStartTime
| where isnotempty(Country)
| sort by SrcIpAddr, Timestamp desc
| serialize
    PrevCountry = prev(Country),
    PrevLat = prev(Latitude),
    PrevLon = prev(Longitude),
    PrevTime = prev(Timestamp)
| where PrevCountry != Country and PrevCountry != ""
| extend
    DistanceMiles = geo_distance_2points(Longitude, Latitude, PrevLon, PrevLat) / 1000 * 0.621371,
    TimeDiffHours = (Timestamp - PrevTime) / 1h,
    RequiredMph = DistanceMiles / TimeDiffHours
| where RequiredMph > MaxMilesPerHour
| project
    CurrentTime = Timestamp,
    CurrentCountry = Country,
    PreviousTime = PrevTime,
    PreviousCountry = PrevCountry,
    DistanceMiles,
    RequiredMph,
    ImpossibleTravel = RequiredMph > MaxMilesPerHour,
    SrcIpAddr
| where ImpossibleTravel
```

**Example Result**:
```
CurrentTime:      2024-02-21 10:30 (Los Angeles, USA)
PreviousTime:     2024-02-21 09:00 (Tokyo, Japan)
TimeDiff:         1.5 hours
DistanceMiles:    5,140 (LA to Tokyo)
RequiredMph:      3,427 (impossible - max is 500)
ImpossibleTravel: TRUE → Account compromised!
```

---

## Advanced Queries

### Query 1: MITRE ATT&CK Mapping

Map detected behaviors to MITRE ATT&CK tactics.

```kql
// Define MITRE ATT&CK mappings
let MitreMapping = datatable(EventType:string, TechID:string, Technique:string, Tactic:string)[
    "ProcessCreate", "T1059", "Command and Scripting Interpreter", "Execution",
    "ProcessCreate", "T1562", "Impair Defenses", "Defense Evasion",
    "NetworkSession", "T1071", "Application Layer Protocol", "Command and Control",
    "NetworkSession", "T1030", "Data Transfer Size Limits", "Exfiltration",
    "ProcessCreate", "T1110", "Brute Force", "Credential Access",
];

// Detect SQL injection (maps to T1190)
_Im_WebSession
| where AttackType == "SqlInjection"
| extend
    TechID = "T1190",
    Technique = "Exploit Public-Facing Application",
    Tactic = "Initial Access"
| project
    EventStartTime,
    SrcIpAddr,
    Url,
    TechID,
    Technique,
    Tactic,
    "SqlInjection" as AttackType
| union (
    // Detect process creation with obfuscation
    _Im_ProcessCreate
    | where CommandLine contains "powershell" and CommandLine contains "-nop" and CommandLine contains "-enc"
    | extend
        TechID = "T1027",
        Technique = "Obfuscated Files or Information",
        Tactic = "Defense Evasion"
    | project
        EventStartTime,
        SrcIpAddr = "",
        Url = ProcessName,
        TechID,
        Technique,
        Tactic,
        "ObfuscatedPowerShell" as AttackType
)
| sort by EventStartTime desc
```

---

### Query 2: Attack Chain Reconstruction

Correlate multiple events into a single attack chain (kill chain).

```kql
// Kill Chain Pattern:
// 1. Reconnaissance -> 2. Initial Access -> 3. Execution -> 4. Persistence -> 5. Privilege Escalation

let Reconnaissance = 
    _Im_NetworkSession
    | where (DstPortNumber in (53, 123, 161) or CommandLine contains "nslookup" or CommandLine contains "ipconfig")
    | project EventStartTime, SrcIpAddr, AttackPhase = "Reconnaissance", Details = DstPortNumber;

let InitialAccess =
    _Im_WebSession
    | where AttackType in ("SqlInjection", "PathTraversal")
    | project EventStartTime, SrcIpAddr, AttackPhase = "InitialAccess", Details = Url;

let Execution =
    _Im_ProcessCreate
    | where ProcessName in ("cmd.exe", "powershell.exe") and TargetUserType != "System"
    | project EventStartTime, SrcIpAddr = "", AttackPhase = "Execution", Details = ProcessName;

let Persistence =
    _Im_ProcessCreate
    | where CommandLine contains "reg add" or CommandLine contains "schtasks"
    | project EventStartTime, SrcIpAddr = "", AttackPhase = "Persistence", Details = CommandLine;

let PrivilegeEscalation =
    _Im_ProcessCreate
    | where ProcessName in ("mimikatz.exe", "laZagne.exe", "procdump.exe")
    | project EventStartTime, SrcIpAddr = "", AttackPhase = "PrivilegeEscalation", Details = ProcessName;

// Combine into attack chain
Reconnaissance
| union Execution
| union InitialAccess
| union Persistence
| union PrivilegeEscalation
| sort by EventStartTime asc
| summarize
    Phases = make_list(AttackPhase),
    FirstSeen = min(EventStartTime),
    LastSeen = max(EventStartTime),
    SourceIP = max(SrcIpAddr)
    by bin(EventStartTime, 1h)
| where array_length(Phases) >= 3  // At least 3 phases = likely real attack
```

---

### Query 3: Anomaly Detection (Baseline Deviation)

```kql
// Establish normal behavior baseline (30 days)
let NormalBehavior = 
    _Im_NetworkSession
    | where TimeGenerated > ago(30d) and TimeGenerated < ago(1d)  // Historical data
    | summarize
        AvgConnections = count(),
        AvgPayload = avg(NumBytes),
        StdDevPayload = stdev(NumBytes),
        TopPorts = make_list(DstPortNumber, 10)
        by SrcIpAddr, DstIpAddr, bin(TimeGenerated, 1h)
    | where AvgConnections > 5;  // Only normal activity

// Compare current day to baseline
_Im_NetworkSession
| where TimeGenerated > ago(24h)
| join kind=leftanti (
    NormalBehavior
) on SrcIpAddr, DstIpAddr, DstPortNumber
// Any connection NOT in historical baseline = anomaly
| where RiskScore_Network >= 75
| project
    EventStartTime,
    SrcIpAddr,
    DstIpAddr,
    DstPortNumber,
    NumBytes,
    "ANOMALOUS" as Classification,
    RiskScore_Network
| sort by RiskScore_Network desc
```

---

## Incident Response Workflows

### Workflow 1: Investigate Raw C2 Alert

When **LSTM fires** a C2 alert:

```kql
// Step 1: Confirm C2 (check for beaconing)
SecurityAlert
| where AlertName == "LSTM_C2_Detection"
| where AlertSeverity in ("High", "Critical")
| extend
    SourceIP = tostring(dynamic_unpack(ExtendedProperties)["SourceIp"]),
    DestIP = tostring(dynamic_unpack(ExtendedProperties)["DestIp"]),
    C2Confidence = toreal(dynamic_unpack(ExtendedProperties)["C2_Probability"])
| where C2Confidence >= 0.80
| join kind=inner (
    // Verify: Multiple connections to same dest
    _Im_NetworkSession
    | where TimeGenerated > ago(1h)
    | summarize
        ConnectionCount = count(),
        AvgDuration = avg(tolong((EventEndTime - EventStartTime) / 1000)),
        LastSeen = max(EventStartTime)
        by SrcIpAddr, DstIpAddr, DstPortNumber
    | where ConnectionCount >= 3  // 3+ connections = beaconing
) on SourceIP == SrcIpAddr, DestIP == DstIpAddr
| project
    TimeGenerated,
    AlertName,
    SourceIP,
    DestIP,
    C2Confidence,
    ConnectionCount,
    AvgDuration,
    "CONFIRMED" as Verdict
```

### Workflow 2: Scope Compromised Systems

When C2 confirmed, find all compromised endpoints:

```kql
// Find all systems that connect to known C2
let KnownC2IPs = dynamic([
    "203.0.113.45",   // Russian FSB
    "203.0.113.46",   // Iranian IRGC
    "203.0.113.47"    // North Korean Bureau 121
]);

_Im_NetworkSession
| where DstIpAddr in (KnownC2IPs)
| summarize
    FirstConnection = min(EventStartTime),
    LastConnection = max(EventStartTime),
    ConnectionCount = count(),
    UniqueDestPorts = dcount(DstPortNumber)
    by SrcIpAddr
| sort by LastConnection desc
// Result: All compromised source IPs
// Action: Disable accounts, isolate devices
```

### Workflow 3: Forensic Timeline

Reconstruct attack timeline:

```kql
// Create unified timeline of all attack indicators
_Im_NetworkSession
| where SrcIpAddr == "10.0.1.5"  // Compromised device
| project
    EventStartTime,
    EventType = "Network",
    SrcIpAddr,
    DstIpAddr,
    DstPortNumber,
    Details = strcat(DstIpAddr, ":", DstPortNumber)
| union (
    _Im_ProcessCreate
    | where TargetUsername contains "domain.com"
    | project
        EventStartTime,
        EventType = "Process",
        SrcIpAddr = "",
        DstIpAddr = "",
        DstPortNumber = 0,
        Details = ProcessName
)
| union (
    _Im_WebSession
    | project
        EventStartTime,
        EventType = "Web",
        SrcIpAddr,
        DstIpAddr = "",
        DstPortNumber = 0,
        Details = Url
)
| sort by EventStartTime asc
| render table
// Shows: Network → Process → Web activity in timeline
```

---

## Study Tips for SC-200

### Understand These Core Concepts

1. **ASIM Architecture**
   - Study the normalization schema
   - Understand why _Im_NetworkSession is better than vendor-specific queries
   - Practice writing union queries that combine sources

2. **Multi-Vendor Threat Hunting**
   - Learn to write ONE query for Palo Alto, Cisco, Azure
   - Understand field mapping (src_ip → SrcIpAddr)
   - Test with sample logs from each vendor

3. **Advanced KQL**
   - Joins (union, inner, leftanti, leftsemi)
   - Time-series analysis (serialize, prev(), next())
   - Aggregations (summarize, make_list, make_set)
   - User-defined functions (let)

4. **MITRE ATT&CK Framework**
   - Know 15 tactics (Reconnaissance → Impact)
   - Understand how alerts map to techniques
   - Use for alert naming convention (T1071 = C2, T1190 = Web exploit)

5. **Incident Response**
   - Containment (isolate device, disable account)
   - Eradication (remove malware, reset password)
   - Recovery (restore from backup, reimage)
   - Root cause analysis (why did this work?)

### Hands-On Practice

1. **Deploy this lab** in Azure:
   ```bash
   terraform apply -target=azurerm_linux_virtual_machine.mde_target_vm
   # Wait 5 min for MDE to register
   # Write KQL query to find it
   ```

2. **Simulate attacks**:
   ```bash
   # From compromised VM, curl to known C2:
   curl http://203.0.113.45:80/c2_beacon
   # Watch LSTM detect it in <30 seconds
   ```

3. **Practice queries**:
   - Write SQL injection detection (using ASIM)
   - Write lateral movement detection
   - Write impossible travel detection

4. **Study official resources**:
   - Microsoft Learn: SC-200 Learning Path
    - ASIM documentation
   - NIST Cybersecurity Framework

---

## Exam Tips

| Topic | How to Master |
|-------|--------------|
| **ASIM** | Understand WHY it's better than vendor-specific queries. Write 5 queries using _Im_* |
| **KQL** | Practice advanced joins. Understand serialize/prev() for timeline analysis |
| **Threat Hunting** | Know MITRE ATT&CK tactics. Map alerts to techniques |
| **Incident Response** | Understand the 4 phases (containment, eradication, recovery, analysis) |
| **Compliance** | Know NIST 800-53 controls (AC, SI, IA, SC) |
| **Performance** | Understand alert optimization, query tuning, cost |
| **Hands-On** | Deploy A.V.A.R.S in your own Azure subscription. Break it, fix it |

---

**You are now prepared for SC-200 certification.** ✅

