#requires -Version 5.1

<#
.SYNOPSIS
    GhostHunt Correlation Engine

.DESCRIPTION
    Correlates multiple independent security findings into a single
    higher-confidence investigation signal.

    This module is read-only and does not modify the endpoint.

.VERSION
    0.1.0
#>

Set-StrictMode -Version Latest

function Get-CorrelationSeverity {

    param(
        [int]$Score
    )

    if ($Score -ge 80) {
        return "Critical"
    }
    elseif ($Score -ge 60) {
        return "High"
    }
    elseif ($Score -ge 40) {
        return "Medium"
    }
    elseif ($Score -ge 20) {
        return "Low"
    }
    else {
        return "Informational"
    }
}

function Get-CorrelationKey {

    param(
        [Parameter(Mandatory = $true)]
        [object]$Finding
    )

    # PID is the strongest correlation identifier.
    if ($Finding.PSObject.Properties.Name -contains "PID") {

        if ($Finding.PID) {
            return "PID:$($Finding.PID)"
        }
    }

    # Fall back to executable path.
    if ($Finding.PSObject.Properties.Name -contains "Path") {

        if (-not [string]::IsNullOrWhiteSpace($Finding.Path)) {
            return "PATH:$($Finding.Path.ToLower())"
        }
    }

    # Fall back to process name.
    if ($Finding.PSObject.Properties.Name -contains "ProcessName") {

        if (-not [string]::IsNullOrWhiteSpace($Finding.ProcessName)) {
            return "PROCESS:$($Finding.ProcessName.ToLower())"
        }
    }

    # Host-level finding.
    return "HOST:$env:COMPUTERNAME"
}

function Invoke-CorrelationEngine {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Findings
    )

    Write-Host ""
    Write-Host "===============================================" -ForegroundColor DarkGray
    Write-Host "             CORRELATION ENGINE" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor DarkGray
    Write-Host ""

    if ($null -eq $Findings -or $Findings.Count -eq 0) {

        Write-Host "[+] No findings supplied for correlation." `
            -ForegroundColor Green

        return @()
    }

    $Groups = @{}

    # -------------------------------------------------------
    # GROUP FINDINGS
    # -------------------------------------------------------

    foreach ($Finding in $Findings) {

        $Key = Get-CorrelationKey -Finding $Finding

        if (-not $Groups.ContainsKey($Key)) {
            $Groups[$Key] = @()
        }

        $Groups[$Key] += $Finding
    }

    $Correlated = @()

    # -------------------------------------------------------
    # ANALYZE EACH GROUP
    # -------------------------------------------------------

    foreach ($Key in $Groups.Keys) {

        $Group = @($Groups[$Key])

        # Only create a correlated alert when multiple
        # independent signals exist.
        $UniqueTypes = @(
            $Group |
            Where-Object {
                $_.PSObject.Properties.Name -contains "DetectionType"
            } |
            Select-Object -ExpandProperty DetectionType -Unique
        )

        if ($UniqueTypes.Count -lt 2) {
            continue
        }

        $Score = 0
        $Reasons = @()
        $Evidence = @()

        # ---------------------------------------------------
        # BASE SIGNAL SCORES
        # ---------------------------------------------------

        foreach ($Type in $UniqueTypes) {

            switch ($Type) {

                "SuspiciousProcessLocation" {
                    $Score += 20
                    $Reasons += "Process executed from a user-writable location."
                }

                "InterestingProcessRelationship" {
                    $Score += 25
                    $Reasons += "Suspicious parent/child process relationship detected."
                }

                "UnsignedExecutable" {
                    $Score += 10
                    $Reasons += "Executable is not digitally signed."
                }

                "UntrustedSignature" {
                    $Score += 25
                    $Reasons += "Executable signature is not trusted."
                }

                "SignatureHashMismatch" {
                    $Score += 40
                    $Reasons += "Executable signature hash does not match the signed content."
                }

                "SignatureValidationError" {
                    $Score += 15
                    $Reasons += "Executable signature validation produced an error."
                }

                "UnusualNetworkActivity" {
                    $Score += 20
                    $Reasons += "Suspicious process has an external network connection."
                }

                "RegistryPersistence" {
                    $Score += 15
                    $Reasons += "Potential registry persistence was discovered."
                }

                "StartupFolderPersistence" {
                    $Score += 15
                    $Reasons += "Potential startup-folder persistence was discovered."
                }

                "SuspiciousScheduledTask" {
                    $Score += 25
                    $Reasons += "Suspicious scheduled task was discovered."
                }

                "SuspiciousService" {
                    $Score += 30
                    $Reasons += "Suspicious Windows service was discovered."
                }

                "WinlogonPersistence" {
                    $Score += 35
                    $Reasons += "Potential Winlogon persistence was discovered."
                }

                default {
                    $Score += 5
                }
            }
        }

        # ---------------------------------------------------
        # CORRELATION BONUS
        # ---------------------------------------------------

        # Multiple independent signals increase confidence.
        $SignalCount = $UniqueTypes.Count

        if ($SignalCount -ge 3) {
            $Score += 15
            $Reasons += "Three or more independent security signals corroborate the finding."
        }

        if ($SignalCount -ge 5) {
            $Score += 10
            $Reasons += "Five or more independent security signals were correlated."
        }

        # Never exceed 100.
        if ($Score -gt 100) {
            $Score = 100
        }

        # ---------------------------------------------------
        # CONFIDENCE
        # ---------------------------------------------------

        $Confidence = 0.50

        foreach ($Finding in $Group) {

            if ($Finding.PSObject.Properties.Name -contains "Confidence") {

                if ($Finding.Confidence -gt $Confidence) {
                    $Confidence = $Finding.Confidence
                }
            }
        }

        # Independent signals increase confidence.
        if ($SignalCount -ge 2) {
            $Confidence += 0.10
        }

        if ($SignalCount -ge 3) {
            $Confidence += 0.10
        }

        if ($SignalCount -ge 4) {
            $Confidence += 0.10
        }

        if ($SignalCount -ge 5) {
            $Confidence += 0.05
        }

        if ($Confidence -gt 0.99) {
            $Confidence = 0.99
        }

        # ---------------------------------------------------
        # EXTRACT COMMON PROCESS INFORMATION
        # ---------------------------------------------------

        $ProcessName = $null
        $PID = $null
        $Path = $null
        $ParentPID = $null

        foreach ($Finding in $Group) {

            if (-not $ProcessName) {
                if ($Finding.PSObject.Properties.Name -contains "ProcessName") {
                    $ProcessName = $Finding.ProcessName
                }
            }

            if (-not $PID) {
                if ($Finding.PSObject.Properties.Name -contains "PID") {
                    $PID = $Finding.PID
                }
            }

            if (-not $Path) {
                if ($Finding.PSObject.Properties.Name -contains "Path") {
                    $Path = $Finding.Path
                }
            }

            if (-not $ParentPID) {
                if ($Finding.PSObject.Properties.Name -contains "ParentPID") {
                    $ParentPID = $Finding.ParentPID
                }
            }
        }

        # ---------------------------------------------------
        # BUILD EVIDENCE
        # ---------------------------------------------------

        foreach ($Finding in $Group) {

            $Evidence += [PSCustomObject]@{
                DetectionType = $Finding.DetectionType
                Severity      = $Finding.Severity
                Confidence    = $Finding.Confidence
                Reason        = $Finding.Reason
            }
        }

        $Severity = Get-CorrelationSeverity -Score $Score

        # ---------------------------------------------------
        # OUTPUT
        # ---------------------------------------------------

        $Result = [PSCustomObject]@{
            DetectionType = "CorrelatedSecuritySignal"
            CorrelationKey = $Key
            Computer      = $env:COMPUTERNAME

            ProcessName   = $ProcessName
            PID           = $PID
            ParentPID     = $ParentPID
            Path          = $Path

            SignalCount   = $SignalCount
            Signals       = ($UniqueTypes -join ", ")

            Score         = $Score
            Severity      = $Severity
            Confidence    = [math]::Round($Confidence, 2)

            Reasons       = ($Reasons -join " ")
            Evidence      = $Evidence

            DetectedAt    = (Get-Date).ToUniversalTime().ToString("o")
        }

        $Correlated += $Result

        Write-Host "[!] CORRELATED SIGNAL" -ForegroundColor Yellow
        Write-Host "    Key        : $Key"
        Write-Host "    Process    : $ProcessName"
        Write-Host "    PID        : $PID"
        Write-Host "    Signals    : $SignalCount"
        Write-Host "    Risk Score : $Score/100"
        Write-Host "    Severity   : $Severity"
        Write-Host "    Confidence : $([math]::Round($Confidence * 100, 0))%"
        Write-Host ""
    }

    Write-Host "-----------------------------------------------"

    if ($Correlated.Count -eq 0) {

        Write-Host "[+] No multi-signal correlations detected." `
            -ForegroundColor Green

    }
    else {

        Write-Host "[!] Correlated alerts: $($Correlated.Count)" `
            -ForegroundColor Yellow
    }

    Write-Host ""

    return $Correlated
}