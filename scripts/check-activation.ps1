Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Check Windows activation status.
try {
    $LicenseInfo = Get-CimInstance -ClassName SoftwareLicensingProduct |
        Where-Object { $_.Name -like "Windows*" -and $_.PartialProductKey }

    if (-not $LicenseInfo -or $LicenseInfo.LicenseStatus -ne 1) {
        Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
        Write-Host "Windows is not activated."
        exit 1
    }
} catch {
    Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
    Write-Host "Failed to check Windows activation status."
    exit 1
}

# Check Windows edition and version.
try {
    $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem

    # Verify Windows 11 Pro.
    if ($OSInfo.Caption -notlike "*Windows 11 Pro*") {
        Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
        Write-Host ("Windows 11 Pro is required. Current edition: {0}." -f $OSInfo.Caption)
        exit 1
    }
} catch {
    Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
    Write-Host "Failed to check Windows edition."
    exit 1
}

# Confirm success.
Write-Host "`nINFO: " -ForegroundColor Cyan -NoNewline
Write-Host ("Edition: {0}." -f $OSInfo.Caption)
Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
Write-Host "System verification passed."