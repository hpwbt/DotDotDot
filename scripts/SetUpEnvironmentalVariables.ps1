Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Check elevation state.
try {
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $IsElevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $IsElevated = $false
}

# Define permanent environmental variables.
$PermanentVariables = @(
    @{ Name = 'NODE_REPL_HISTORY'; Value = ' '; Scope = 'Machine' },
    @{ Name = 'PYTHON_HISTORY'; Value = ' '; Scope = 'Machine' }
)

# Set permanent environmental variables.
foreach ($var in $PermanentVariables) {
    $requiresElevation = $var.Scope -eq 'Machine'

    if ($requiresElevation -and -not $IsElevated) {
        Write-Host "`nWARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host ("Skipped setting {0}. Requires elevation." -f $var.Name)
        continue
    }

    try {
        [Environment]::SetEnvironmentVariable($var.Name, $var.Value, $var.Scope)
        Write-Host "`nSUCCESS: " -ForegroundColor Green -NoNewline
        Write-Host ("{0} set." -f $var.Name)
        Write-Host "INFO: " -ForegroundColor Cyan -NoNewline
        Write-Host ("Value: `"{0}`"." -f $var.Value)
    } catch {
        Write-Host "`nWARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host ("Failed to set {0}." -f $var.Name)
    }
}

# Set LIBREPROFILE for current session.
$ProfilesRootPath = Join-Path $env:APPDATA 'LibreWolf\Profiles'

if (Test-Path -LiteralPath $ProfilesRootPath) {
    $ProfileMatches = @(Get-ChildItem -Path $ProfilesRootPath -Directory -Filter '*.default-default')

    if ($ProfileMatches.Count -eq 1) {
        $env:LIBREPROFILE = $ProfileMatches[0].FullName
        Write-Host "`nSUCCESS: " -ForegroundColor Green -NoNewline
        Write-Host "LIBREPROFILE set for current session."
        Write-Host "INFO: " -ForegroundColor Cyan -NoNewline
        Write-Host ("Path: {0}." -f $env:LIBREPROFILE)
    } elseif ($ProfileMatches.Count -gt 1) {
        Write-Host "`nWARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host "Skipped setting LIBREPROFILE. Multiple default-default LibreWolf profiles found."
    }
}

exit 0