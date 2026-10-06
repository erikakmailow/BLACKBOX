#requires -Version 5.1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "                  GHOSTHUNT" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[+] Host: $env:COMPUTERNAME"
Write-Host "[+] User: $env:USERNAME"
Write-Host ""

# -------------------------------------------------------
# LOAD MODULES
# -------------------------------------------------------

$ModulePath = Join-Path $PSScriptRoot "Modules"

$Modules = @(
    "ProcessHunt.ps1"
    "ProcessDNA.ps1"
    "ProcessTree.ps1"
    "SignatureHunt.ps1"
    "NetworkHunt.ps1"
    "CorrelationEngine.ps1"
    "RiskEngine.ps1"
)

Write-Host "[*] Loading modules..."

foreach ($Module in $Modules) {

    $FullPath = Join-Path $ModulePath $Module

    if (Test-Path $FullPath) {

        . $FullPath

        Write-Host "[+] Loaded: $Module" -ForegroundColor Green
    }
    else {

        Write-Host "[!] Missing: $Module" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "[+] Module loading complete." -ForegroundColor Green
Write-Host ""

# -------------------------------------------------------
# DETECTION
# -------------------------------------------------------

$AllFindings = @()

Write-Host "===============================================" -ForegroundColor DarkGray
Write-Host "              DETECTION PHASE" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor DarkGray
Write-Host ""

Write-Host "[*] Running ProcessHunt..."
$AllFindings += @(Invoke-ProcessHunt)

Write-Host "[*] Running ProcessTree..."
$AllFindings += @(Invoke-ProcessTreeHunt)

Write-Host "[*] Running SignatureHunt..."
$AllFindings += @(Invoke-SignatureHunt)

Write-Host "[*] Running NetworkHunt..."
$AllFindings += @(Invoke-NetworkHunt)

Write-Host ""
Write-Host "[+] Detection phase complete." -ForegroundColor Green
Write-Host "[+] Total raw findings: $($AllFindings.Count)"
Write-Host ""

# -------------------------------------------------------
# CORRELATION
# -------------------------------------------------------

Write-Host "===============================================" -ForegroundColor DarkGray
Write-Host "             CORRELATION PHASE" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor DarkGray
Write-Host ""

$CorrelatedFindings = @(
    Invoke-CorrelationEngine -Findings $AllFindings
)

# -------------------------------------------------------
# RISK ANALYSIS
# -------------------------------------------------------

Write-Host "===============================================" -ForegroundColor DarkGray
Write-Host "               RISK ANALYSIS" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor DarkGray
Write-Host ""

$RiskResults = @(
    Invoke-RiskEngine -Findings $AllFindings
)

# -------------------------------------------------------
# SUMMARY
# -------------------------------------------------------

Write-Host "===============================================" -ForegroundColor DarkGray
Write-Host "              GHOSTHUNT SUMMARY" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor DarkGray
Write-Host ""

Write-Host "Host              : $env:COMPUTERNAME"
Write-Host "Raw Findings      : $($AllFindings.Count)"
Write-Host "Correlated Alerts : $($CorrelatedFindings.Count)"
Write-Host "Risk Assessments  : $($RiskResults.Count)"
Write-Host ""

if ($CorrelatedFindings.Count -gt 0) {

    Write-Host "[!] CORRELATED ALERTS" -ForegroundColor Yellow
    Write-Host ""

    foreach ($Alert in $CorrelatedFindings) {

        Write-Host "-----------------------------------------------"
        Write-Host "Process    : $($Alert.ProcessName)"
        Write-Host "PID        : $($Alert.PID)"
        Write-Host "Signals    : $($Alert.SignalCount)"
        Write-Host "Score      : $($Alert.Score)/100"
        Write-Host "Severity   : $($Alert.Severity)"
        Write-Host "Confidence : $([math]::Round($Alert.Confidence * 100, 0))%"
        Write-Host ""
    }
}
else {

    Write-Host "[+] No correlated alerts detected." -ForegroundColor Green
}

Write-Host ""
Write-Host "===============================================" -ForegroundColor DarkGray
Write-Host "[+] GhostHunt scan complete." -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor DarkGray
Write-Host ""