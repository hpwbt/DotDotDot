Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Display setting message.
Write-Host "`nINFO: " -ForegroundColor Cyan -NoNewline
Write-Host "Setting environment variables . . ."

# Check elevation state.
try {
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $IsElevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $IsElevated = $false
}

# Define permanent environment variables.
$PermanentVariables = @(
    @{ Name = 'NODE_REPL_HISTORY'; Value = ' '; Scope = 'Machine' },
    @{ Name = 'PYTHON_HISTORY'; Value = ' '; Scope = 'Machine' }
)

# Set permanent environment variables.
foreach ($var in $PermanentVariables) {
    $requiresElevation = $var.Scope -eq 'Machine'

    if ($requiresElevation -and -not $IsElevated) {
        Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host ("Skipped setting [{0}]. Requires elevation." -f $var.Name)
        continue
    }

    try {
        [Environment]::SetEnvironmentVariable($var.Name, $var.Value, $var.Scope)
        Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
        Write-Host ("[{0}] set." -f $var.Name)
    } catch {
        Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host ("Failed to set [{0}]." -f $var.Name)
    }
}

# Set LIBREPROFILE for current session.
$ProfilesRootPath = Join-Path $env:APPDATA 'LibreWolf\Profiles'

if (-not (Test-Path -LiteralPath $ProfilesRootPath)) {
    Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
    Write-Host "Skipped setting [LIBREPROFILE]. LibreWolf profiles directory not found."
} else {
    $ProfileMatches = @(Get-ChildItem -Path $ProfilesRootPath -Directory -Filter '*.default-default')

    if ($ProfileMatches.Count -eq 0) {
        Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host "Skipped setting [LIBREPROFILE]. No default-default LibreWolf profiles found."
    } elseif ($ProfileMatches.Count -eq 1) {
        $env:LIBREPROFILE = $ProfileMatches[0].FullName
        Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
        Write-Host "[LIBREPROFILE] set for current session."
    } else {
        Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host "Skipped setting [LIBREPROFILE]. Multiple default-default LibreWolf profiles found."
    }
}

exit 0