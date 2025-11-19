Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Display verification message.
Write-Host "`nINFO: " -ForegroundColor Cyan -NoNewline
Write-Host "Verifying that Windows is activated with a Pro license . . ."

try {
    # Check activation status and edition.
    $LicenseInfo = Get-CimInstance -ClassName SoftwareLicensingProduct |
        Where-Object { $_.Name -like "Windows*" -and $_.PartialProductKey }
    $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem

    if (-not $LicenseInfo -or $LicenseInfo.LicenseStatus -ne 1) {
        Write-Host "ERROR: " -ForegroundColor Red -NoNewline
        Write-Host "Windows is not activated."
        exit 1
    }

    if ($OSInfo.Caption -notlike "*Windows 11 Pro*") {
        Write-Host "ERROR: " -ForegroundColor Red -NoNewline
        Write-Host "Windows is not activated."
        exit 1
    }

    # Confirm success.
    Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
    Write-Host "Windows is activated."
} catch {
    Write-Host "ERROR: " -ForegroundColor Red -NoNewline
    Write-Host "Windows is not activated."
    exit 1
}