#requires -Version 5.1

<#
.SYNOPSIS
    GhostHunt Process Tree Analyzer

.DESCRIPTION
    Builds a parent/child process tree and identifies potentially
    suspicious process relationships.

    Read-only. No processes are terminated or modified.

.VERSION
    0.1.0
#>

Set-StrictMode -Version Latest

function Invoke-ProcessTreeHunt {

    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "===============================================" -ForegroundColor DarkGray
    Write-Host "              PROCESS TREE HUNT" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor DarkGray
    Write-Host ""

    $Processes = Get-CimInstance Win32_Process

    # -------------------------------------------------------
    # BUILD PROCESS LOOKUP TABLE
    # -------------------------------------------------------

    $ProcessMap = @{}

    foreach ($Process in $Processes) {

        $ProcessMap[$Process.ProcessId] = $Process
    }

    # -------------------------------------------------------
    # INTERESTING PARENT/CHILD COMBINATIONS
    # -------------------------------------------------------

    $InterestingParents = @(
        "winword.exe"
        "excel.exe"
        "outlook.exe"
        "powerpnt.exe"
        "acrord32.exe"
        "chrome.exe"
        "msedge.exe"
        "firefox.exe"
        "teams.exe"
        "onenote.exe"
    )

    $InterestingChildren = @(
        "powershell.exe"
        "pwsh.exe"
        "cmd.exe"
        "wscript.exe"
        "cscript.exe"
        "mshta.exe"
        "rundll32.exe"
        "regsvr32.exe"
        "certutil.exe"
    )

    $Findings = @()

    # -------------------------------------------------------
    # ANALYZE RELATIONSHIPS
    # -------------------------------------------------------

    foreach ($Process in $Processes) {

        $ParentPID = $Process.ParentProcessId

        if (-not $ProcessMap.ContainsKey($ParentPID)) {
            continue
        }

        $Parent = $ProcessMap[$ParentPID]

        if (
            ($InterestingParents -contains $Parent.Name.ToLower()) -and
            ($InterestingChildren -contains $Process.Name.ToLower())
        ) {

            Write-Host "[!] INTERESTING PROCESS RELATIONSHIP" `
                -ForegroundColor Yellow

            Write-Host ""
            Write-Host "    Parent : $($Parent.Name)"
            Write-Host "    PID    : $($Parent.ProcessId)"
            Write-Host ""
            Write-Host "    Child  : $($Process.Name)"
            Write-Host "    PID    : $($Process.ProcessId)"
            Write-Host ""
            Write-Host "    Command:"
            Write-Host "    $($Process.CommandLine)"
            Write-Host ""

            $Findings += [PSCustomObject]@{

                DetectionType = "InterestingProcessRelationship"

                Severity = "High"

                Confidence = 0.85

                ParentProcess = $Parent.Name

                ParentPID = $Parent.ProcessId

                ChildProcess = $Process.Name

                ChildPID = $Process.ProcessId

                ChildPath = $Process.ExecutablePath

                CommandLine = $Process.CommandLine

                Computer = $env:COMPUTERNAME

                DetectedAt = (
                    Get-Date
                ).ToUniversalTime().ToString("o")
            }
        }
    }

    # -------------------------------------------------------
    # SUMMARY
    # -------------------------------------------------------

    Write-Host "-----------------------------------------------"

    if ($Findings.Count -eq 0) {

        Write-Host "[+] No high-interest process relationships detected." `
            -ForegroundColor Green
    }
    else {

        Write-Host "[!] Interesting relationships: $($Findings.Count)" `
            -ForegroundColor Yellow
    }

    Write-Host ""

    return $Findings
}

function Get-ProcessChain {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$ProcessId
    )

    $Processes = Get-CimInstance Win32_Process

    $ProcessMap = @{}

    foreach ($Process in $Processes) {
        $ProcessMap[$Process.ProcessId] = $Process
    }

    $Chain = @()

    $CurrentPID = $ProcessId

    while ($ProcessMap.ContainsKey($CurrentPID)) {

        $Current = $ProcessMap[$CurrentPID]

        $Chain += [PSCustomObject]@{
            Name = $Current.Name
            PID = $Current.ProcessId
            ParentPID = $Current.ParentProcessId
            Path = $Current.ExecutablePath
            CommandLine = $Current.CommandLine
        }

        if ($Current.ParentProcessId -eq 0) {
            break
        }

        $CurrentPID = $Current.ParentProcessId
    }

    return $Chain
}