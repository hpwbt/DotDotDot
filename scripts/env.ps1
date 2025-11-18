Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Locate LibreWolf profiles directory.
$ProfilesRootPath = Join-Path $env:APPDATA 'LibreWolf\Profiles'
if (-not (Test-Path -LiteralPath $ProfilesRootPath)) {
    throw "ERROR: LibreWolf profiles directory not found."
}

# Find exactly one *.default-default profile.
$ProfileMatches = @(Get-ChildItem -Path $ProfilesRootPath -Directory -Filter '*.default-default')

if ($ProfileMatches.Count -eq 0) {
    throw "ERROR: No *.default-default profile found."
}

if ($ProfileMatches.Count -gt 1) {
    throw "ERROR: Multiple default-default profiles found."
}

# Set LIBREPROFILE environment variable.
$env:LIBREPROFILE = $ProfileMatches[0].FullName

# Confirm success.
Write-Host "`nSUCCESS: " -ForegroundColor Green -NoNewline
Write-Host "Environment variable successfully set."
Write-Host "INFO: " -ForegroundColor Cyan -NoNewline
Write-Host ("LIBREPROFILE = `"{0}`"." -f $env:LIBREPROFILE)