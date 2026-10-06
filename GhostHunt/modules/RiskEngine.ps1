#requires -Version 5.1

<#
.SYNOPSIS
    GhostHunt Risk Engine

.DESCRIPTION
    Calculates an explainable risk score from GhostHunt findings.

.VERSION
    0.2.0
#>

Set-StrictMode -Version Latest

function Get-RiskSeverity {

    param(
        [Parameter(Mandatory = $true)]
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

function Get-FindingScore {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Finding
    )

    $Score = 0
    $Reasons = @()

    switch ($Finding.DetectionType) {

        "SuspiciousProcessLocation" {
            $Score += 25
            $Reasons += "Process executed from a potentially user-writable location."
        }

        "InterestingProcessRelationship" {
            $Score += 35
            $Reasons += "Interesting parent/child process relationship detected."
        }

        "UnsignedExecutable" {
            $Score += 15
            $Reasons += "Executable is not digitally signed."
        }

        "UntrustedSignature" {
            $Score += 30
            $Reasons += "Executable signature is not trusted."
        }

        "SignatureHashMismatch" {
            $Score += 50
            $Reasons += "Executable signature hash does not match the signed content."
        }

        "SignatureValidationError" {
            $Score += 20
            $Reasons += "Executable signature validation encountered an error."
        }

        "IncompatibleSignature" {
            $Score += 15
            $Reasons += "Executable has an incompatible signature state."
        }

        "SuspiciousCommandLine" {
            $Score += 25
            $Reasons += "Suspicious command-line characteristics detected."
        }

        "RegistryPersistence" {
            $Score += 15
            $Reasons += "Potential registry persistence discovered."
        }

        "StartupFolderPersistence" {
            $Score += 15
            $Reasons += "Potential startup-folder persistence discovered."
        }

        "SuspiciousScheduledTask" {
            $Score += 30
            $Reasons += "Potentially suspicious scheduled task discovered."
        }

        "SuspiciousService" {
            $Score += 35
            $Reasons += "Potentially suspicious Windows service discovered."
        }

        "WinlogonPersistence" {
            $Score += 40
            $Reasons += "Potential Winlogon persistence discovered."
        }

        "UnusualNetworkActivity" {
            $Score += 20
            $Reasons += "Command interpreter or scripting process has an external network connection."
        }

        "EncodedPowerShell" {
            $Score += 30
            $Reasons += "PowerShell command contains an encoded-command indicator."
        }

        "SignatureAnomaly" {
            $Score += 10
            $Reasons += "Executable signature state requires investigation."
        }

        default {
            $Score += 5
            $Reasons += "Unclassified security finding."
        }
    }

    # Confidence adjustment
    if ($Finding.PSObject.Properties.Name -contains "Confidence") {

        if ($Finding.Confidence -ge 0.90) {
            $Score += 10
            $Reasons += "Detection has high confidence."
        }
        elseif ($Finding.Confidence -ge 0.75) {
            $Score += 5
            $Reasons += "Detection has moderate-high confidence."
        }
    }

    if ($Score -gt 100) {
        $Score = 100
    }

    [PSCustomObject]@{
        Score   = $Score
        Severity = Get-RiskSeverity -Score $Score
        Reasons = $Reasons
    }
}

function Invoke-RiskEngine {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Findings
    )

    $Results = @()

    if ($null -eq $Findings -or $Findings.Count -eq 0) {
        return $Results
    }

    foreach ($Finding in $Findings) {

        $Risk = Get-FindingScore -Finding $Finding

        $Results += [PSCustomObject]@{
            DetectionType = $Finding.DetectionType
            ProcessName   = if ($Finding.PSObject.Properties.Name -contains "ProcessName") {
                $Finding.ProcessName
            }
            else {
                $null
            }

            PID = if ($Finding.PSObject.Properties.Name -contains "PID") {
                $Finding.PID
            }
            else {
                $null
            }

            Score    = $Risk.Score
            Severity = $Risk.Severity
            Reasons  = ($Risk.Reasons -join " ")
        }
    }

    return $Results
}