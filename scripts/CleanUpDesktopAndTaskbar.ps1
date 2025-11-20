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

# Clear taskbar registry data.
$TaskbarRegPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband'
if (Test-Path $TaskbarRegPath) {
    try {
        Remove-Item -Path $TaskbarRegPath -Recurse -Force
        Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
        Write-Host "Taskbar registry data cleared."
    } catch {
        Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host "Failed to clear taskbar registry data."
    }
}

exit 0