#requires -Version 5.1

<#
.SYNOPSIS
    GhostHunt network activity hunter.

.DESCRIPTION
    Correlates active TCP connections with their owning
    processes and identifies external connections associated
    with scripting or command-interpreter processes.

    Read-only. No network connections are modified.

.VERSION
    0.2.0
#>

Set-StrictMode -Version Latest

function Invoke-NetworkHunt {

    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "===============================================" -ForegroundColor DarkGray
    Write-Host "               NETWORK HUNT" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor DarkGray
    Write-Host ""

    $Findings = @()

    $InterestingProcesses = @(
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

    try {
        $Connections = @(Get-NetTCPConnection -ErrorAction Stop)
    }
    catch {
        Write-Host "[!] Unable to retrieve TCP connections." `
            -ForegroundColor Yellow

        return @()
    }

    $Processes = @(
        Get-CimInstance Win32_Process
    )

    foreach ($Connection in $Connections) {

        # Ignore loopback traffic.
        if (
            $Connection.RemoteAddress -eq "127.0.0.1" -or
            $Connection.RemoteAddress -eq "::1" -or
            $Connection.RemoteAddress -eq "0.0.0.0"
        ) {
            continue
        }

        $ProcessId = $Connection.OwningProcess

        if ($ProcessId -eq 0) {
            continue
        }

        $Process = $Processes |
            Where-Object {
                $_.ProcessId -eq $ProcessId
            } |
            Select-Object -First 1

        if ($null -eq $Process) {
            continue
        }

        if ($InterestingProcesses -notcontains $Process.Name.ToLower()) {
            continue
        }

        $Path = $Process.ExecutablePath
        $User = $null

        try {

            $OwnerResult = Invoke-CimMethod `
                -InputObject $Process `
                -MethodName GetOwner `
                -ErrorAction SilentlyContinue

            if ($OwnerResult.User) {
                $User = "$($OwnerResult.Domain)\$($OwnerResult.User)"
            }
        }
        catch {
        }

        Write-Host "[!] NETWORK FINDING" -ForegroundColor Yellow
        Write-Host "    Process       : $($Process.Name)"
        Write-Host "    PID           : $ProcessId"
        Write-Host "    User          : $User"
        Write-Host "    Local         : $($Connection.LocalAddress):$($Connection.LocalPort)"
        Write-Host "    Remote        : $($Connection.RemoteAddress):$($Connection.RemotePort)"
        Write-Host "    State         : $($Connection.State)"
        Write-Host "    Path          : $Path"
        Write-Host ""

        $Findings += [PSCustomObject]@{
            DetectionType = "UnusualNetworkActivity"
            Severity      = "Medium"
            Confidence    = 0.65

            ProcessName   = $Process.Name
            PID           = $ProcessId
            ParentPID     = $Process.ParentProcessId

            Path          = $Path
            CommandLine   = $Process.CommandLine
            User          = $User

            LocalAddress  = $Connection.LocalAddress
            LocalPort     = $Connection.LocalPort
            RemoteAddress = $Connection.RemoteAddress
            RemotePort    = $Connection.RemotePort
            State         = $Connection.State

            Reason = "Command interpreter or scripting process has an external network connection."

            Computer   = $env:COMPUTERNAME
            DetectedAt = (Get-Date).ToUniversalTime().ToString("o")
        }
    }

    Write-Host "-----------------------------------------------"

    if ($Findings.Count -eq 0) {

        Write-Host "[+] No unusual scripting-process network activity detected." `
            -ForegroundColor Green
    }
    else {

        Write-Host "[!] Network findings: $($Findings.Count)" `
            -ForegroundColor Yellow
    }

    Write-Host ""

    return $Findings
}