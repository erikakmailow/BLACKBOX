#requires -Version 5.1

<#
.SYNOPSIS
    GhostHunt persistence inventory.

.DESCRIPTION
    Read-only inventory of common Windows startup locations.
#>

Set-StrictMode -Version Latest

function Invoke-PersistenceHunt {

    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "===============================================" -ForegroundColor DarkGray
    Write-Host "              PERSISTENCE HUNT" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor DarkGray
    Write-Host ""

    $Findings = @()

    # -------------------------------------------------------
    # USER STARTUP FOLDER
    # -------------------------------------------------------

    $StartupFolders = @()

    try {
        $StartupFolders += [Environment]::GetFolderPath("Startup")
    }
    catch {
    }

    if ($env:ProgramData) {

        $StartupFolders += Join-Path `
            $env:ProgramData `
            "Microsoft\Windows\Start Menu\Programs\Startup"
    }

    foreach ($Folder in $StartupFolders) {

        if (-not (Test-Path $Folder)) {
            continue
        }

        try {

            $Items = Get-ChildItem -Path $Folder -File -ErrorAction SilentlyContinue

            foreach ($Item in $Items) {

                $Findings += [PSCustomObject]@{
                    DetectionType = "StartupFolderPersistence"
                    Severity      = "Medium"
                    Confidence    = 0.65
                    Name          = $Item.Name
                    Value         = $Item.FullName
                    Path          = $Item.FullName
                    Reason        = "Executable or shortcut found in a Windows startup folder."
                    Computer      = $env:COMPUTERNAME
                    DetectedAt    = (Get-Date).ToUniversalTime().ToString("o")
                }
            }
        }
        catch {
        }
    }

    # -------------------------------------------------------
    # REGISTRY STARTUP LOCATIONS
    # -------------------------------------------------------

    $RegistryLocations = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    foreach ($Location in $RegistryLocations) {

        if (-not (Test-Path $Location)) {
            continue
        }

        try {

            $Properties = Get-ItemProperty `
                -Path $Location `
                -ErrorAction SilentlyContinue

            if ($null -eq $Properties) {
                continue
            }

            foreach ($Property in $Properties.PSObject.Properties) {

                if ($Property.Name -like "PS*") {
                    continue
                }

                $Value = [string]$Property.Value

                if ([string]::IsNullOrWhiteSpace($Value)) {
                    continue
                }

                $Findings += [PSCustomObject]@{
                    DetectionType = "RegistryPersistence"
                    Severity      = "Medium"
                    Confidence    = 0.70
                    Name          = $Property.Name
                    Value         = $Value
                    Path          = $Location
                    Reason        = "Startup registry entry discovered."
                    Computer      = $env:COMPUTERNAME
                    DetectedAt    = (Get-Date).ToUniversalTime().ToString("o")
                }
            }
        }
        catch {
        }
    }

    # -------------------------------------------------------
    # SUMMARY
    # -------------------------------------------------------

    Write-Host "-----------------------------------------------"

    if ($Findings.Count -eq 0) {

        Write-Host "[+] No startup entries discovered." `
            -ForegroundColor Green
    }
    else {

        Write-Host "[!] Startup entries discovered: $($Findings.Count)" `
            -ForegroundColor Yellow
    }

    Write-Host ""

    return $Findings
}