Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Display update message.
Write-Host "`nINFO: " -ForegroundColor Cyan -NoNewline
Write-Host "Updating winget . . ."

# Define paths.
$ApiUrl = 'https://api.github.com/repos/microsoft/winget-cli/releases/latest'
$uuid = [guid]::NewGuid().ToString().ToLower()
$TempDownloadPath = Join-Path $env:TEMP "$uuid.msixbundle"

# Get latest release info from GitHub API.
try {
    $releaseInfo = Invoke-RestMethod -Uri $ApiUrl -UseBasicParsing
    Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
    Write-Host ("Latest release found: {0}." -f $releaseInfo.tag_name)
} catch {
    Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
    Write-Host "Failed to fetch latest release info from GitHub."
    exit 1
}

# Find the .msixbundle asset.
$msixAsset = $releaseInfo.assets | Where-Object { $_.name -like '*.msixbundle' } | Select-Object -First 1

if (-not $msixAsset) {
    Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
    Write-Host "No .msixbundle file found in latest release."
    exit 1
}

# Download the .msixbundle file.
Write-Host "`nINFO: " -ForegroundColor Cyan -NoNewline
Write-Host "Downloading winget installer . . ."

try {
    Invoke-WebRequest -Uri $msixAsset.browser_download_url -OutFile $TempDownloadPath -UseBasicParsing
    Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
    Write-Host "Installer downloaded."
} catch {
    Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
    Write-Host "Failed to download installer."
    exit 1
}

# Install the package.
Write-Host "`nINFO: " -ForegroundColor Cyan -NoNewline
Write-Host "Installing winget . . ."

try {
    Add-AppxPackage -Path $TempDownloadPath -ForceUpdateFromAnyVersion
    Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
    Write-Host "Winget updated successfully."
} catch {
    Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
    Write-Host "Failed to install winget."
    exit 1
}

# Clean up temp file.
try {
    Remove-Item -LiteralPath $TempDownloadPath -Force
} catch {
    # Non-critical, don't exit.
}

exit 0