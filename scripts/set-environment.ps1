Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Locate LibreWolf profiles directory.
$ProfilesRootPath = Join-Path $env:APPDATA 'LibreWolf\Profiles'

if (-not (Test-Path -LiteralPath $ProfilesRootPath)) {
    exit 0
}

# Find exactly one *.default-default profile.
$ProfileMatches = @(Get-ChildItem -Path $ProfilesRootPath -Directory -Filter '*.default-default')

if ($ProfileMatches.Count -eq 0) {
    exit 0
}

if ($ProfileMatches.Count -gt 1) {
    Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
    Write-Host "Multiple default-default profiles found."
    exit 1
}

# Set LIBREPROFILE environment variable.
$env:LIBREPROFILE = $ProfileMatches[0].FullName

# Confirm success.
Write-Host "`nSUCCESS: " -ForegroundColor Green -NoNewline
Write-Host "Environment variable successfully set."
Write-Host "INFO: " -ForegroundColor Cyan -NoNewline
Write-Host ("LIBREPROFILE = `"{0}`"." -f $env:LIBREPROFILE)