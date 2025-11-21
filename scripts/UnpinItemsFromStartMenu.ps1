Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Display cleanup message.
Write-Host "`nINFO: " -ForegroundColor Cyan -NoNewline
Write-Host "Unpinning Start Menu items . . ."

# Define Start Menu layout path.
$layoutPath = Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState'

try {
    if (Test-Path -LiteralPath $layoutPath) {
        # Remove all files in the LocalState directory to reset Start Menu layout.
        Get-ChildItem -LiteralPath $layoutPath -File -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
            } catch {
                # Best effort - continue on any error.
            }
        }
    }
} catch {
    # Best effort - continue on any error.
}

exit 0