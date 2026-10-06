#requires -Version 5.1

<#
.SYNOPSIS
    GhostHunt executable signature hunter.

.DESCRIPTION
    Reviews signatures of currently running processes.

    Valid signatures are treated as normal.
    Unsigned or abnormal signatures are returned as findings.

.VERSION
    0.2.0
#>

Set-StrictMode -Version Latest

function Invoke-SignatureHunt {

    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "===============================================" -ForegroundColor DarkGray
    Write-Host "              SIGNATURE HUNT" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor DarkGray
    Write-Host ""

    $Findings = @()

    $Processes = Get-CimInstance Win32_Process

    foreach ($Process in $Processes) {

        $Path = $Process.ExecutablePath

        if ([string]::IsNullOrWhiteSpace($Path)) {
            continue
        }

        if (-not (Test-Path $Path)) {
            continue
        }

        try {
            $Signature = Get-AuthenticodeSignature -FilePath $Path
        }
        catch {
            continue
        }

        $Status = [string]$Signature.Status

        # Valid signatures are normal.
        if ($Status -eq "Valid") {
            continue
        }

        $Severity = "Medium"
        $Confidence = 0.50
        $Reason = "Executable signature requires investigation."

        switch ($Status) {

            "NotSigned" {
                $Severity = "Low"
                $Confidence = 0.40
                $Reason = "Executable is not digitally signed."
            }

            "HashMismatch" {
                $Severity = "High"
                $Confidence = 0.90
                $Reason = "Executable content does not match its digital signature."
            }

            "NotTrusted" {
                $Severity = "High"
                $Confidence = 0.80
                $Reason = "Executable signature is not trusted."
            }

            "UnknownError" {
                $Severity = "Medium"
                $Confidence = 0.60
                $Reason = "Windows could not validate the executable signature."
            }

            "Incompatible" {
                $Severity = "Medium"
                $Confidence = 0.60
                $Reason = "Executable has an incompatible signature."
            }
        }

        $DetectionType = switch ($Status) {

            "NotSigned" {
                "UnsignedExecutable"
            }

            "HashMismatch" {
                "SignatureHashMismatch"
            }

            "NotTrusted" {
                "UntrustedSignature"
            }

            "UnknownError" {
                "SignatureValidationError"
            }

            "Incompatible" {
                "IncompatibleSignature"
            }

            default {
                "SignatureAnomaly"
            }
        }

        $Publisher = $null

        if ($null -ne $Signature.SignerCertificate) {
            $Publisher = $Signature.SignerCertificate.Subject
        }

        Write-Host "[!] SIGNATURE FINDING" -ForegroundColor Yellow
        Write-Host "    Process   : $($Process.Name)"
        Write-Host "    PID       : $($Process.ProcessId)"
        Write-Host "    Status    : $Status"
        Write-Host "    Publisher : $Publisher"
        Write-Host "    Path      : $Path"
        Write-Host "    Reason    : $Reason"
        Write-Host ""

        $Findings += [PSCustomObject]@{
            DetectionType = $DetectionType
            Severity      = $Severity
            Confidence    = $Confidence

            ProcessName   = $Process.Name
            PID           = $Process.ProcessId
            ParentPID     = $Process.ParentProcessId

            Path          = $Path
            CommandLine   = $Process.CommandLine

            SignatureStatus = $Status
            Publisher       = $Publisher

            Reason        = $Reason
            Computer      = $env:COMPUTERNAME
            DetectedAt    = (Get-Date).ToUniversalTime().ToString("o")
        }
    }

    Write-Host "-----------------------------------------------"

    if ($Findings.Count -eq 0) {

        Write-Host "[+] No abnormal executable signatures detected." `
            -ForegroundColor Green
    }
    else {

        Write-Host "[!] Signature findings: $($Findings.Count)" `
            -ForegroundColor Yellow
    }

    Write-Host ""

    return $Findings
}