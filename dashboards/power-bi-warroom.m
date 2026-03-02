// =============================================================================
// POWER BI DASHBOARD: A.V.A.R.S SECURITY WAR ROOM
// Real-time threat visualization + compliance health
// Data sources: Azure Monitor, Sentinel, ML model predictions
// =============================================================================

// This is the M (Power Query) code for Power BI
// Import from Azure Log Analytics using Analytics connector

// ============================================================================
// 1. LIVE THREAT MAP
// Geographic view of attacks with AI risk scores
// ============================================================================

let 
    LiveThreats = 
    (
        SecurityEvent
        | where TimeGenerated > ago(24h)
        | extend
            GeoIP = 
            case(
                SourceIp startswith "192.168", "Internal",
                SourceIp startswith "10.", "Internal",
                SourceIp startswith "172.16", "Internal",
                // Simplified - in production use GeoIP lookup service
                "External"
            ),
            ThreatCountry = 
            case(
                GeoIP == "Internal", "Headquarters",
                SourceIp startswith "185.220", "Tor Network",
                "Internet"
            ),
            AIRiskScore = 
            case(
                Activity contains "C2", 0.95,
                Activity contains "BruteForce", 0.85,
                Activity contains "SQLInjection", 0.90,
                Activity contains "Lateral", 0.80,
                Activity contains "Reconnaissance", 0.65,
                0.3
            ),
            IncidentSeverity = 
            case(
                AIRiskScore > 0.9, "🔴 CRITICAL",
                AIRiskScore > 0.8, "🟠 HIGH",
                AIRiskScore > 0.6, "🟡 MEDIUM",
                "🟢 LOW"
            )
        | project
            TimeGenerated,
            SourceIp,
            Activity,
            TargetAccount,
            ThreatCountry,
            AIRiskScore,
            IncidentSeverity,
            AccountCount = 1,
            EventCount = 1
    )

in LiveThreats;

// ============================================================================
// 2. LSTM C2 DETECTION DASHBOARD
// Real-time predictions from LSTM model
// ============================================================================

let
    LSTMPredictions =
    (
        SecurityAlert
        | where AlertName == "LSTM_C2_Detection"
        | where TimeGenerated > ago(24h)
        | extend
            C2Probability = tofloat(extract(@"probability['\"]?\s*:\s*(\d+\.?\d*)", 1, Entities)),
            DetectionMethod = "LSTM Neural Network",
            TrafficPattern = extract(@"pattern['\"]?\s*:\s*['\"](\w+)['\"]", 1, Entities),
            SequenceLength = 60,
            ConfidenceLevel = 
            case(
                C2Probability > 0.95, "Very High ⭐⭐⭐⭐⭐",
                C2Probability > 0.85, "High ⭐⭐⭐⭐",
                C2Probability > 0.70, "Moderate ⭐⭐⭐",
                "Low"
            )
        | project
            TimeGenerated,
            AlertName,
            C2Probability,
            ConfidenceLevel,
            TrafficPattern,
            SourceIp = tostring(parse_json(tostring(parse_json(Entities)[0]))),
            AlertSeverity,
            DetectionMethod
    )

in LSTMPredictions;

// ============================================================================
// 3. COMPLIANCE HEALTH SCORECARD
// Control coverage and satisfaction metrics
// ============================================================================

let
    ComplianceHealth =
    (
        SecurityAlert
        | where TimeGenerated > ago(30d)
        | extend
            ControlType = 
            case(
                AlertName contains "C2", "SI-4",
                AlertName contains "BruteForce", "AC-2",
                AlertName contains "SQL", "SI-4",
                AlertName contains "Lateral", "CA-3",
                AlertName contains "Exfiltration", "CA-7",
                "AC-2"
            ),
            FrameworkApplies = "NIST, ISO27001, PCI-DSS"
        | summarize
            ControlsTestedCount = dcount(ControlType),
            IncidentsDetected = count(),
            CriticalAlerts = countif(AlertSeverity == "Critical")
        | extend
            ComplianceCoveragePercentage = 
            case(
                ControlsTestedCount >= 15, 100,
                ControlsTestedCount >= 10, 75,
                ControlsTestedCount >= 5, 50,
                25
            ),
            ComplianceStatus = 
            case(
                ComplianceCoveragePercentage >= 90, "🟢 Compliant",
                ComplianceCoveragePercentage >= 75, "🟡 Mostly Compliant",
                ComplianceCoveragePercentage >= 50, "🟠 Needs Attention",
                "🔴 Non-Compliant"
            ),
            HealthScore = strcat(tostring(ComplianceCoveragePercentage), "%"),
            LastAudit = now(),
            NextAuditDue = now() + 7d
        | project
            ComplianceStatus,
            HealthScore,
            ControlsTestedCount,
            IncidentsDetected,
            CriticalAlerts,
            LastAudit,
            NextAuditDue
    )

in ComplianceHealth;

// ============================================================================
// 4. INCIDENT RESPONSE TIME METRICS
// How quickly are we responding to detected threats?
// ============================================================================

let
    ResponseMetrics =
    (
        SecurityAlert
        | where TimeGenerated > ago(30d)
        | extend
            DetectionTime = TimeGenerated,
            ResponseTime = datetime_diff("minute", now(), TimeGenerated),
            ResponseCategory = 
            case(
                ResponseTime < 5, "Automated (< 5 min)",
                ResponseTime < 60, "Fast (< 1 hour)",
                ResponseTime < 480, "Normal (< 8 hours)",
                "Slow (> 8 hours)"
            ),
            IncidentClass = 
            case(
                AlertSeverity == "Critical", "Critical Path",
                AlertSeverity == "High", "High Priority",
                "Standard"
            )
        | summarize
            IncidentCount = count(),
            AvgResponseMinutes = avg(ResponseTime),
            FastResponses = countif(ResponseTime < 60),
            AutomatedResponses = countif(ResponseTime < 5)
            by ResponseCategory, IncidentClass
    )

in ResponseMetrics;

// ============================================================================
// 5. THREAT INTELLIGENCE CORRELATION
// Shows which detected attacks match known threat feeds
// ============================================================================

let
    ThreatIntelCorrelation =
    (
        SecurityAlert
        | where TimeGenerated > ago(7d)
        | extend
            SourceIPReputation = 
            case(
                SourceIp in ("185.220.101.0", "185.220.102.0"), "Known Tor Exit Node",
                SourceIp startswith "192.0.2", "Honeypot Traffic",
                SourceIp startswith "203.0.113", "Known C2 Infrastructure",
                "Unknown"
            ),
            ThreatActorGroup = 
            case(
                AlertName contains "APT", "APT Group",
                AlertName contains "Ransomware", "Ransomware Gang",
                SourceIPReputation contains "Tor", "Anonymized Attacker",
                "Unattributed"
            ),
            IntelSource = "AlienVault OTX, MISP, abuse.ch"
        | where SourceIPReputation != "Unknown"
        | summarize
            AlertCount = count(),
            UniqueIPs = dcount(SourceIp),
            AffectedAccounts = dcount(TargetAccount),
            MaxSeverity = max(AlertSeverity)
            by ThreatActorGroup, SourceIPReputation, IntelSource
    )

in ThreatIntelCorrelation;

// ============================================================================
// 6. CONTROL EFFECTIVENESS BREAKDOWN
// Shows which NIST controls are being effectively tested
// ============================================================================

let
    ControlEffectiveness =
    (
        SecurityAlert
        | where TimeGenerated > ago(90d)
        | extend
            NISTControl = 
            case(
                AlertName contains "SQLInjection", "SI-4",
                AlertName contains "BruteForce", "AC-2",
                AlertName contains "C2", "SI-4",
                AlertName contains "Lateral", "CA-3",
                AlertName contains "Privilege", "AC-6",
                AlertName contains "Exfiltration", "CA-7",
                "AC-2"
            ),
            ControlDescription = 
            case(
                NISTControl == "SI-4", "System Monitoring",
                NISTControl == "AC-2", "Account Management",
                NISTControl == "CA-3", "System Interconnections",
                NISTControl == "AC-6", "Least Privilege",
                NISTControl == "CA-7", "Continuous Monitoring",
                "Unknown"
            )
        | summarize
            TimesTestedByIncidents = count(),
            UniqueIncidentTypes = dcount(AlertName),
            AffectedResources = dcount(ResourceId),
            HighSeverityTests = countif(AlertSeverity == "High" or AlertSeverity == "Critical")
            by NISTControl, ControlDescription
        | extend
            ControlQuality = 
            case(
                TimesTestedByIncidents >= 10 and UniqueIncidentTypes >= 3, "Robust Testing",
                TimesTestedByIncidents >= 5 and UniqueIncidentTypes >= 2, "Good Testing",
                TimesTestedByIncidents >= 2, "Basic Testing",
                "Limited Testing"
            )
    )

in ControlEffectiveness;

// ============================================================================
// 7. EXECUTIVE DASHBOARD SUMMARY
// High-level KPIs for leadership briefing
// ============================================================================

let
    ExecutiveSummary = 
    (
        SecurityAlert
        | where TimeGenerated > ago(24h)
        | extend
            IncidentDate = format_datetime(TimeGenerated, 'yyyy-MM-dd HH:mm'),
            WeekNumber = week_of_year(TimeGenerated)
        | summarize
            TotalIncidents24h = count(),
            CriticalIncidents = countif(AlertSeverity == "Critical"),
            HighIncidents = countif(AlertSeverity == "High"),
            SuspiciousUsers = dcount(TargetAccount),
            CompromisedResources = dcount(ResourceId),
            AutomatedResponsesTriggered = countif(AlertName contains "AutoResponse")
        | extend
            IncidentTrendline = 
            case(
                TotalIncidents24h > 20, "🔴 High Activity",
                TotalIncidents24h > 10, "🟠 Elevated Activity",
                TotalIncidents24h > 5, "🟡 Normal",
                "🟢 Quiet"
            ),
            ResponseAutomationRate = ((AutomatedResponsesTriggered / TotalIncidents24h) * 100),
            SecurityPosture = 
            case(
                CriticalIncidents == 0 and HighIncidents < 2, "Strong 💪",
                CriticalIncidents == 0 and HighIncidents < 5, "Good ✅",
                CriticalIncidents == 0 and HighIncidents < 10, "Fair ⚠️",
                "Weak 🚨"
            )
        | project
            TotalIncidents24h,
            CriticalIncidents,
            HighIncidents,
            SuspiciousUsers,
            CompromisedResources,
            AutomatedResponsesTriggered,
            AutomationRate = strcat(tostring(round(ResponseAutomationRate, 2)), "%"),
            IncidentTrendline,
            SecurityPosture,
            UpdateTime = now(),
            ReportingPeriod = "Last 24 Hours"
    )

in ExecutiveSummary;

// ============================================================================
// USAGE INSTRUCTIONS FOR POWER BI
// ============================================================================

/*
POWER BI DASHBOARD SETUP:

1. Create new report in Power BI
2. Add data source: Azure Log Analytics workspace
3. Create pages:

   PAGE 1: EXECUTIVE SUMMARY
   - KPI cards (TotalIncidents24h, CriticalIncidents, AutomationRate)
   - Big number visualization for SecurityPosture
   - Line chart: Incident trend over last 7 days

   PAGE 2: THREAT MAP (War Room)
   - Map visualization: SourceIp → ThreatCountry color-coded by AIRiskScore
   - Table: Top threats with C2Probability scores
   - Gauge: Compliance Health Score

   PAGE 3: C2 DETECTION DETAILS
   - Time series: C2Probability over time (red line at 0.8 threshold)
   - Table: LSTM detections with confidence levels
   - KPI: Detections in last 24h / 7d / 30d

   PAGE 4: CONTROL COMPLIANCE
   - Bar chart: ControlsTestedCount by Framework
   - Table: Control Effectiveness breakdown
   - Gauge: ComplianceCoveragePercentage

   PAGE 5: RESPONSE METRICS
   - Clustered bar: ResponseCategory vs IncidentCount
   - Average response time KPI
   - Automated response rate gauge

   PAGE 6: THREAT INTELLIGENCE
   - Table: ThreatActorGroup with IP reputation
   - Map: Geographic distribution of threats
   - Timeline: Detected threats over time

REFRESH RATE: Every 5 minutes
AUDIENCE: CISO, Security Team leads, Compliance officers
DISTRIBUTION: Teams, SharePoint, Power BI Service
*/
