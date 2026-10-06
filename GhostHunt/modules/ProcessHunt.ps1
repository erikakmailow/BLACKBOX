#requires -Version 5.1

<#
.SYNOPSIS
    GhostHunt Process Hunter

.DESCRIPTION
    Performs read-only process analysis and identifies processes
    executing from potentially suspicious locations.

    This module does NOT terminate processes or make changes
    to the endpoint.

.VERSION
    0.1.0
#>

Set-StrictMode -Version Latest

function Invoke-ProcessHunt {

    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "===============================================" -ForegroundColor DarkGray
    Write-Host "              PROCESS HUNT" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor DarkGray
    Write-Host ""

    $Findings = @()

    # Get running processes with command-line information.
    $Processes = Get-CimInstance Win32_Process

    foreach ($Process in $Processes) {

        $Path = $Process.ExecutablePath

        # Some Windows processes don't expose an executable path.
        if ([string]::IsNullOrWhiteSpace($Path)) {
            continue
        }

        # -------------------------------------------------------
        # CHECK 1: USER-WRITABLE LOCATIONS
        # -------------------------------------------------------

        $SuspiciousLocation = $false
        $Reason = $null

        if ($Path -match '\\Users\\[^\\]+\\AppData\\Local\\Temp\\') {

            $SuspiciousLocation = $true
            $Reason = "Executable running from user Temp directory"

        }
        elseif ($Path -match '\\Users\\[^\\]+\\AppData\\Roaming\\') {

            $SuspiciousLocation = $true
            $Reason = "Executable running from user Roaming profile"

        }
        elseif ($Path -match '\\Users\\Public\\') {

            $SuspiciousLocation = $true
            $Reason = "Executable running from Public user directory"

        }
        elseif ($Path -match '\\Windows\\Temp\\') {

            $SuspiciousLocation = $true
            $Reason = "Executable running from Windows Temp directory"
        }

        if ($SuspiciousLocation) {

            Write-Host "[!] SUSPICIOUS PROCESS" -ForegroundColor Yellow

            Write-Host "    Process : $($Process.Name)"
            Write-Host "    PID     : $($Process.ProcessId)"
            Write-Host "    Parent  : $($Process.ParentProcessId)"
            Write-Host "    Path    : $Path"
            Write-Host "    Reason  : $Reason"
            Write-Host ""

            $Findings += [PSCustomObject]@{
                DetectionType = "SuspiciousProcessLocation"
                Severity      = "Medium"
                Confidence    = 0.70
                ProcessName   = $Process.Name
                PID           = $Process.ProcessId
                ParentPID     = $Process.ParentProcessId
                Path          = $Path
                CommandLine   = $Process.CommandLine
                Reason        = $Reason
                Computer      = $env:COMPUTERNAME
                DetectedAt    = (Get-Date).ToUniversalTime().ToString("o")
            }
        }
    }

    # -------------------------------------------------------
    # SUMMARY
    # -------------------------------------------------------

    Write-Host "-----------------------------------------------"

    if ($Findings.Count -eq 0) {

        Write-Host "[+] No suspicious process locations detected." `
            -ForegroundColor Green

    }
    else {

        Write-Host "[!] Findings: $($Findings.Count)" `
            -ForegroundColor Yellow
    }

    Write-Host ""

    return $Findings
}