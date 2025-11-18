Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Check elevation state.
try {
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $isElevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $isElevated = $false
}

# Set NODE_REPL_HISTORY at system level if elevated.
if ($isElevated) {
    try {
        [Environment]::SetEnvironmentVariable('NODE_REPL_HISTORY', ' ', 'Machine')
        Write-Host "`nSUCCESS: " -ForegroundColor Green -NoNewline
        Write-Host "NODE_REPL_HISTORY set."
        Write-Host "INFO: " -ForegroundColor Cyan -NoNewline
        Write-Host "Value: `" `" (single space)."
    } catch {
        Write-Host "`nWARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host "Failed to set NODE_REPL_HISTORY."
    }
} else {
    Write-Host "`nWARNING: " -ForegroundColor Yellow -NoNewline
    Write-Host "Skipped NODE_REPL_HISTORY. Requires elevation."
}

# Set LIBREPROFILE for current session.
$profilesRootPath = Join-Path $env:APPDATA 'LibreWolf\Profiles'

if (-not (Test-Path -LiteralPath $profilesRootPath)) {
    exit 0
}

$profileMatches = @(Get-ChildItem -Path $profilesRootPath -Directory -Filter '*.default-default')

if ($profileMatches.Count -eq 0) {
    exit 0
}

if ($profileMatches.Count -gt 1) {
    Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
    Write-Host "Multiple default-default LibreWolf profiles found."
    exit 1
}

$env:LIBREPROFILE = $profileMatches[0].FullName
Write-Host "`nSUCCESS: " -ForegroundColor Green -NoNewline
Write-Host "LIBREPROFILE set for current session."
Write-Host "INFO: " -ForegroundColor Cyan -NoNewline
Write-Host ("Path: {0}." -f $env:LIBREPROFILE)

exit 0