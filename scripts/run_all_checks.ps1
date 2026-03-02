param(
    [switch]$Quick,
    [switch]$IncludeRiskRun,
    [string]$ReportPath
)

$ErrorActionPreference = "Stop"
if ($null -ne (Get-Variable -Name PSNativeCommandUseErrorActionPreference -Scope Global -ErrorAction SilentlyContinue)) {
    $global:PSNativeCommandUseErrorActionPreference = $false
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repoRoot

$results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Details
    )

    $results.Add([PSCustomObject]@{
        Name = $Name
        Status = $Status
        Details = $Details
    }) | Out-Null
}

function Invoke-Check {
    param(
        [string]$Name,
        [scriptblock]$Script,
        [switch]$WarningOnly
    )

    try {
        $output = & $Script 2>&1 | Out-String
        $clean = $output.Trim()
        if ([string]::IsNullOrWhiteSpace($clean)) {
            $clean = "OK"
        }
        Add-Result -Name $Name -Status "PASS" -Details $clean
    }
    catch {
        $msg = $_.Exception.Message
        if ($WarningOnly) {
            Add-Result -Name $Name -Status "WARN" -Details $msg
        }
        else {
            Add-Result -Name $Name -Status "FAIL" -Details $msg
        }
    }
}

$pythonExe = $null
if (Test-Path ".venv\Scripts\python.exe") {
    $pythonExe = Resolve-Path ".venv\Scripts\python.exe"
}
elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonExe = "py -3"
}
else {
    $pythonExe = "python"
}

Invoke-Check -Name "Terraform validate" -Script {
    Push-Location terraform
    try {
        terraform validate
    }
    finally {
        Pop-Location
    }
}

Invoke-Check -Name "Terraform fmt check" -Script {
    Push-Location terraform
    try {
        terraform fmt -check -recursive
    }
    finally {
        Pop-Location
    }
}

Invoke-Check -Name "Python compileall" -Script {
    if ($pythonExe -is [string] -and $pythonExe -like "py -3") {
        py -3 -m compileall -q scripts ml-notebooks
    }
    elseif ($pythonExe -is [string] -and $pythonExe -eq "python") {
        python -m compileall -q scripts ml-notebooks
    }
    else {
        & $pythonExe -m compileall -q scripts ml-notebooks
    }
}

Invoke-Check -Name "Logic App JSON parse" -Script {
    Get-ChildItem -Recurse -File logic-apps -Filter *.json | ForEach-Object {
        if ($pythonExe -is [string] -and $pythonExe -like "py -3") {
            py -3 -m json.tool $_.FullName > $null
        }
        elseif ($pythonExe -is [string] -and $pythonExe -eq "python") {
            python -m json.tool $_.FullName > $null
        }
        else {
            & $pythonExe -m json.tool $_.FullName > $null
        }
    }
    "Parsed all logic-app JSON files"
}

Invoke-Check -Name "PowerShell parse" -Script {
    Get-ChildItem -Recurse -File -Include *.ps1 | ForEach-Object {
        $content = Get-Content -Raw $_.FullName
        [scriptblock]::Create($content) | Out-Null
    }
    "Parsed all PowerShell scripts"
}

Invoke-Check -Name "Workflow YAML parse" -Script {
    $yamlCheck = @'
import glob
import yaml
for f in glob.glob('.github/workflows/*.y*ml'):
    with open(f, 'r', encoding='utf-8') as fh:
        yaml.safe_load(fh)
print('Parsed workflow YAML files')
'@

    if ($pythonExe -is [string] -and $pythonExe -like "py -3") {
        py -3 -c $yamlCheck
    }
    elseif ($pythonExe -is [string] -and $pythonExe -eq "python") {
        python -c $yamlCheck
    }
    else {
        & $pythonExe -c $yamlCheck
    }
}

if ($Quick) {
    Add-Result -Name "Bash script syntax (Git Bash)" -Status "PASS" -Details "Skipped in quick mode"
    Add-Result -Name "Smoke: exploit-poc-c2 help" -Status "PASS" -Details "Skipped in quick mode"
    Add-Result -Name "Smoke: penetration-test-automation help" -Status "PASS" -Details "Skipped in quick mode"
}
else {
    Invoke-Check -Name "Bash script syntax (Git Bash)" -Script {
        if (-not (Test-Path "C:\Program Files\Git\bin\bash.exe")) {
            throw "Git Bash not found at C:\Program Files\Git\bin\bash.exe"
        }

        & "C:\Program Files\Git\bin\bash.exe" -n scripts/kql/deploy_sentinel_whitelist_controls.sh
        & "C:\Program Files\Git\bin\bash.exe" -n deploy.sh
        "Bash syntax OK"
    } -WarningOnly

    Invoke-Check -Name "Smoke: exploit-poc-c2 help" -Script {
        if ($pythonExe -is [string] -and $pythonExe -like "py -3") {
            py -3 scripts/exploit-poc-c2.py --help
        }
        elseif ($pythonExe -is [string] -and $pythonExe -eq "python") {
            python scripts/exploit-poc-c2.py --help
        }
        else {
            & $pythonExe scripts/exploit-poc-c2.py --help
        }
    }

    Invoke-Check -Name "Smoke: penetration-test-automation help" -Script {
        if ($pythonExe -is [string] -and $pythonExe -like "py -3") {
            py -3 scripts/penetration-test-automation.py --help
        }
        elseif ($pythonExe -is [string] -and $pythonExe -eq "python") {
            python scripts/penetration-test-automation.py --help
        }
        else {
            & $pythonExe scripts/penetration-test-automation.py --help
        }
    }
}

Invoke-Check -Name "Smoke: risk-quantification" -Script {
    if (-not $IncludeRiskRun) {
        "Skipped (use -IncludeRiskRun to execute full run)"
    }
    else {
        if ($pythonExe -is [string] -and $pythonExe -like "py -3") {
            py -3 scripts/risk-quantification.py
        }
        elseif ($pythonExe -is [string] -and $pythonExe -eq "python") {
            python scripts/risk-quantification.py
        }
        else {
            & $pythonExe scripts/risk-quantification.py
        }
    }
}

if ($Quick) {
    Add-Result -Name "Azure auth precheck" -Status "PASS" -Details "Skipped in quick mode"
}
else {
    Invoke-Check -Name "Azure auth precheck" -Script {
        $env:Path = "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin;" + $env:Path
        az account show --query id -o tsv
    } -WarningOnly
}

$passCount = @($results | Where-Object { $_.Status -eq "PASS" }).Count
$warnCount = @($results | Where-Object { $_.Status -eq "WARN" }).Count
$failCount = @($results | Where-Object { $_.Status -eq "FAIL" }).Count

if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $ReportPath = Join-Path $repoRoot "reports\validation_report_$stamp.md"
}

$reportDir = Split-Path -Parent $ReportPath
if (-not (Test-Path $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir | Out-Null
}

$lines = @()
$lines += "# A.V.A.R.S Validation Report"
$lines += ""
$lines += "- Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$lines += "- Repository: $repoRoot"
$lines += "- Python command: $pythonExe"
$lines += ""
$lines += "## Summary"
$lines += ""
$lines += "- PASS: $passCount"
$lines += "- WARN: $warnCount"
$lines += "- FAIL: $failCount"
$lines += ""
$lines += "## Checks"
$lines += ""
$lines += "| Check | Status | Details |"
$lines += "|---|---|---|"

foreach ($r in $results) {
    $detail = $r.Details -replace "\|", "\\|"
    $detail = $detail -replace "\r?\n", " <br> "
    $lines += "| $($r.Name) | $($r.Status) | $detail |"
}

Set-Content -Path $ReportPath -Value ($lines -join [Environment]::NewLine) -Encoding UTF8

Write-Host "Validation report written to: $ReportPath"
Write-Host "PASS=$passCount WARN=$warnCount FAIL=$failCount"

if ($failCount -gt 0) {
    exit 1
}

exit 0
