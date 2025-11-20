Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Display cleanup message.
Write-Host "`nINFO: " -ForegroundColor Cyan -NoNewline
Write-Host "Cleaning up desktop and taskbar . . ."

# Define target directories.
$UserDesktopPath = Join-Path $env:USERPROFILE 'Desktop'
$PublicDesktopPath = 'C:\Users\Public\Desktop'
$TaskbarPinsPath = Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar'
$TaskbarImplicitPath = Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch\User Pinned\ImplicitAppShortcuts'

# Define XML layout file paths.
$UserLayoutXmlPath = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Shell\LayoutModification.xml'
$DefaultLayoutXmlPath = 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml'

# Clean user desktop.
if (Test-Path -LiteralPath $UserDesktopPath) {
    try {
        $items = @(Get-ChildItem -LiteralPath $UserDesktopPath -Force)
        if ($items.Count -gt 0) {
            $items | Remove-Item -Recurse -Force
            Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
            Write-Host "User desktop cleared."
        } else {
            Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
            Write-Host "User desktop already empty."
        }
    } catch {
        Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host "Failed to clear user desktop."
    }
} else {
    Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
    Write-Host "User desktop directory not found."
}

# Clean public desktop.
if (Test-Path -LiteralPath $PublicDesktopPath) {
    try {
        $items = @(Get-ChildItem -LiteralPath $PublicDesktopPath -Force)
        if ($items.Count -gt 0) {
            $items | Remove-Item -Recurse -Force
            Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
            Write-Host "Public desktop cleared."
        } else {
            Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
            Write-Host "Public desktop already empty."
        }
    } catch {
        Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host "Failed to clear public desktop."
    }
} else {
    Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
    Write-Host "Public desktop directory not found."
}

# Clean taskbar pins.
if (Test-Path -LiteralPath $TaskbarPinsPath) {
    try {
        $items = @(Get-ChildItem -LiteralPath $TaskbarPinsPath -Force)
        if ($items.Count -gt 0) {
            $items | Remove-Item -Recurse -Force
            Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
            Write-Host "Taskbar pins cleared."
        } else {
            Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
            Write-Host "Taskbar already empty."
        }
    } catch {
        Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host "Failed to clear taskbar pins."
    }
} else {
    Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
    Write-Host "Taskbar pins directory not found."
}

# Clean implicit app shortcuts (UWP/Store apps).
if (Test-Path -LiteralPath $TaskbarImplicitPath) {
    try {
        $items = @(Get-ChildItem -LiteralPath $TaskbarImplicitPath -Force)
        if ($items.Count -gt 0) {
            $items | Remove-Item -Recurse -Force
            Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
            Write-Host "Implicit taskbar shortcuts cleared."
        }
    } catch {
        Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host "Failed to clear implicit taskbar shortcuts."
    }
}

# Remove user layout XML file to prevent auto-pinning.
if (Test-Path -LiteralPath $UserLayoutXmlPath) {
    try {
        Remove-Item -LiteralPath $UserLayoutXmlPath -Force
        Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
        Write-Host "User taskbar layout file removed."
    } catch {
        Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host "Failed to remove user taskbar layout file."
    }
}

# Remove default layout XML file to prevent auto-pinning.
if (Test-Path -LiteralPath $DefaultLayoutXmlPath) {
    try {
        Remove-Item -LiteralPath $DefaultLayoutXmlPath -Force
        Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
        Write-Host "Default taskbar layout file removed."
    } catch {
        Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host "Failed to remove default taskbar layout file."
    }
}

exit 0