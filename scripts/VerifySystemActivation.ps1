Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Display verification message.
Write-Host "`nINFO: " -ForegroundColor Cyan -NoNewline
Write-Host "Verifying that Windows is activated with a Pro license."

# Check Windows activation status.
Write-Host "INFO: " -ForegroundColor Cyan -NoNewline
Write-Host "Checking activation status. . ."
try {
    $LicenseInfo = Get-CimInstance -ClassName SoftwareLicensingProduct |
        Where-Object { $_.Name -like "Windows*" -and $_.PartialProductKey }
    if (-not $LicenseInfo -or $LicenseInfo.LicenseStatus -ne 1) {
        Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
        Write-Host "Verification failed."
        exit 1
    }
} catch {
    Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
    Write-Host "Verification failed."
    exit 1
}

# Check Windows edition and version.
Write-Host "INFO: " -ForegroundColor Cyan -NoNewline
Write-Host "Checking Windows edition. . ."
try {
    $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    if ($OSInfo.Caption -notlike "*Windows 11 Pro*") {
        Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
        Write-Host "Verification failed."
        exit 1
    }
} catch {
    Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
    Write-Host "Verification failed."
    exit 1
}

# Confirm success.
Write-Host "`nSUCCESS: " -ForegroundColor Green -NoNewline
Write-Host "Verification passed."