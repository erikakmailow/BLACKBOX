#requires -Version 5.1

<#
.SYNOPSIS
    GhostHunt ProcessDNA

.DESCRIPTION
    Builds a detailed identity profile for running processes.

    This module is read-only. It does not terminate processes,
    modify files, or change system configuration.

.VERSION
    0.1.0
#>

Set-StrictMode -Version Latest

function Get-ProcessDNA {

    [CmdletBinding()]
    param(
        [int]$ProcessId
    )

    Write-Host ""
    Write-Host "===============================================" -ForegroundColor DarkGray
    Write-Host "                 PROCESS DNA" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor DarkGray
    Write-Host ""

    # -------------------------------------------------------
    # GET PROCESS
    # -------------------------------------------------------

    $Process = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId"

    if (-not $Process) {

        Write-Host "[!] Process $ProcessId was not found." `
            -ForegroundColor Red

        return
    }

    $Path = $Process.ExecutablePath

    if ([string]::IsNullOrWhiteSpace($Path)) {

        Write-Host "[!] Process does not expose an executable path." `
            -ForegroundColor Yellow

        return
    }

    # -------------------------------------------------------
    # FILE INFORMATION
    # -------------------------------------------------------

    $FileInfo = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue

    if (-not $FileInfo) {

        Write-Host "[!] Unable to access executable." `
            -ForegroundColor Yellow

        return
    }

    # -------------------------------------------------------
    # HASH
    # -------------------------------------------------------

    $Hash = Get-FileHash `
        -LiteralPath $Path `
        -Algorithm SHA256 `
        -ErrorAction SilentlyContinue

    # -------------------------------------------------------
    # DIGITAL SIGNATURE
    # -------------------------------------------------------

    $Signature = Get-AuthenticodeSignature `
        -LiteralPath $Path `
        -ErrorAction SilentlyContinue

    # -------------------------------------------------------
    # PARENT PROCESS
    # -------------------------------------------------------

    $ParentProcess = Get-CimInstance Win32_Process `
        -Filter "ProcessId = $($Process.ParentProcessId)"

    # -------------------------------------------------------
    # PROCESS OWNER
    # -------------------------------------------------------

    $Owner = Invoke-CimMethod `
        -InputObject $Process `
        -MethodName GetOwner `
        -ErrorAction SilentlyContinue

    if ($Owner.User) {

        $ProcessOwner = "$($Owner.Domain)\$($Owner.User)"

    }
    else {

        $ProcessOwner = "Unknown"
    }

    # -------------------------------------------------------
    # BUILD PROCESS DNA
    # -------------------------------------------------------

    $DNA = [PSCustomObject]@{

        ComputerName = $env:COMPUTERNAME

        ProcessName = $Process.Name

        ProcessId = $Process.ProcessId

        ParentProcessId = $Process.ParentProcessId

        ParentProcessName = if ($ParentProcess) {
            $ParentProcess.Name
        }
        else {
            "Unknown"
        }

        Owner = $ProcessOwner

        ExecutablePath = $Path

        CommandLine = $Process.CommandLine

        SHA256 = if ($Hash) {
            $Hash.Hash
        }
        else {
            "Unavailable"
        }

        SignatureStatus = if ($Signature) {
            $Signature.Status.ToString()
        }
        else {
            "Unknown"
        }

        Publisher = if ($Signature.SignerCertificate) {
            $Signature.SignerCertificate.Subject
        }
        else {
            "Unknown"
        }

        FileSize = $FileInfo.Length

        CreationTime = $FileInfo.CreationTime

        LastWriteTime = $FileInfo.LastWriteTime

        CollectedAt = (Get-Date).ToUniversalTime().ToString("o")
    }

    # -------------------------------------------------------
    # DISPLAY
    # -------------------------------------------------------

    Write-Host "Process Information" -ForegroundColor Cyan
    Write-Host "-------------------"

    Write-Host "Name       : $($DNA.ProcessName)"
    Write-Host "PID        : $($DNA.ProcessId)"
    Write-Host "Parent     : $($DNA.ParentProcessName)"
    Write-Host "Parent PID : $($DNA.ParentProcessId)"
    Write-Host "Owner      : $($DNA.Owner)"
    Write-Host ""

    Write-Host "Executable" -ForegroundColor Cyan
    Write-Host "----------"

    Write-Host "Path       : $($DNA.ExecutablePath)"
    Write-Host "SHA256     : $($DNA.SHA256)"
    Write-Host "Signature  : $($DNA.SignatureStatus)"
    Write-Host "Publisher  : $($DNA.Publisher)"
    Write-Host ""

    Write-Host "File Metadata" -ForegroundColor Cyan
    Write-Host "-------------"

    Write-Host "Size       : $($DNA.FileSize) bytes"
    Write-Host "Created    : $($DNA.CreationTime)"
    Write-Host "Modified   : $($DNA.LastWriteTime)"
    Write-Host ""

    return $DNA
}