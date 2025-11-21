Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Display download message.
Write-Host "`nINFO: " -ForegroundColor Cyan -NoNewline
Write-Host "Downloading DotDotDot from GitHub . . ."

# Define paths.
$RepoUrl = 'https://github.com/hpwbt/DotDotDot/archive/refs/heads/main.zip'
$uuid = [guid]::NewGuid().ToString().ToLower()
$TempZipPath = Join-Path $env:TEMP "$uuid.zip"
$TempExtractPath = Join-Path $env:TEMP "$uuid-extract"
$TargetPath = Join-Path $env:TEMP $uuid

# Download repository.
try {
    Invoke-WebRequest -Uri $RepoUrl -OutFile $TempZipPath -UseBasicParsing
    Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
    Write-Host "Repository downloaded."
} catch {
    Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
    Write-Host "Failed to download repository."
    exit 1
}

# Extract archive.
Write-Host "`nINFO: " -ForegroundColor Cyan -NoNewline
Write-Host "Extracting files . . ."

try {
    Expand-Archive -Path $TempZipPath -DestinationPath $TempExtractPath -Force
    Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
    Write-Host "Files extracted."
} catch {
    Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
    Write-Host "Failed to extract files."
    exit 1
}

# Move extracted folder to target location.
Write-Host "`nINFO: " -ForegroundColor Cyan -NoNewline
Write-Host "Installing DotDotDot . . ."

try {
    # GitHub extracts to DotDotDot-main folder.
    $ExtractedFolderPath = Join-Path $TempExtractPath 'DotDotDot-main'

    # Move extracted folder to target location.
    Move-Item -LiteralPath $ExtractedFolderPath -Destination $TargetPath -Force
    Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
    Write-Host ("DotDotDot installed to '{0}'." -f $TargetPath)
} catch {
    Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
    Write-Host "Failed to install DotDotDot."
    exit 1
}

# Clean up temp files.
try {
    Remove-Item -LiteralPath $TempZipPath -Force
    Remove-Item -LiteralPath $TempExtractPath -Recurse -Force
} catch {
    # Non-critical, don't exit.
}

# Launch orchestrator.
Write-Host "`nINFO: " -ForegroundColor Cyan -NoNewline
Write-Host "Launching orchestrator . . ."

$OrchestratorPath = Join-Path $TargetPath 'orchestrator.bat'

if (-not (Test-Path -LiteralPath $OrchestratorPath)) {
    Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
    Write-Host ("Orchestrator not found at '{0}'." -f $OrchestratorPath)
    exit 1
}

try {
    Start-Process -FilePath $OrchestratorPath -WindowStyle Maximized
    Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
    Write-Host "Orchestrator launched."
} catch {
    Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
    Write-Host "Failed to launch orchestrator."
    exit 1
}

exit 0