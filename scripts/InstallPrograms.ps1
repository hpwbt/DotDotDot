Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Display installation message.
Write-Host "`nINFO: " -ForegroundColor Cyan -NoNewline
Write-Host "Installing programs . . ."

# Define programs to install.
$ProgramsToInstall = @(
    'Microsoft.VisualStudioCode'
)

# Install each program.
foreach ($programId in $ProgramsToInstall) {
    try {
        # Run winget install with silent flag and suppress msstore errors.
        & winget install --id $programId --silent --accept-source-agreements --accept-package-agreements --source winget 2>$null
    } catch {
        # Best effort - continue on any error.
    }
}

exit 0