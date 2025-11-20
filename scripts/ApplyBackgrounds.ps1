Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Display setting message.
Write-Host "`nINFO: " -ForegroundColor Cyan -NoNewline
Write-Host "Setting wallpaper and lock screen . . ."

# Resolve paths from script location.
$ScriptDirPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$DotDotDotRootPath = Split-Path $ScriptDirPath -Parent
$StoreRootPath = Join-Path $DotDotDotRootPath 'store'

# Verify we're running from inside %USERPROFILE%\DotDotDot.
$ExpectedDirPath = Join-Path $env:USERPROFILE 'DotDotDot'
if ($DotDotDotRootPath -ne $ExpectedDirPath) {
    Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
    Write-Host ("This script must be run in '{0}'. Currently it's running in '{1}'." -f $ExpectedDirPath, $DotDotDotRootPath)
    exit 1
}

# Check elevation state.
try {
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $IsElevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $IsElevated = $false
}

# Set wallpaper.
$WallpaperSourceDir = Join-Path $StoreRootPath 'Windows Explorer\Wallpaper'
$WallpaperDestDir = Join-Path $env:USERPROFILE 'Pictures\Wallpaper'

if (-not (Test-Path -LiteralPath $WallpaperSourceDir)) {
    Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
    Write-Host "Skipped wallpaper. Source directory not found."
} else {
    $wallpaperFiles = @(Get-ChildItem -LiteralPath $WallpaperSourceDir -File)

    if ($wallpaperFiles.Count -eq 0) {
        Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host "Skipped wallpaper. No file found in store."
    } elseif ($wallpaperFiles.Count -gt 1) {
        Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host "Skipped wallpaper. Multiple files found in store."
    } else {
        try {
            if (-not (Test-Path -LiteralPath $WallpaperDestDir)) {
                New-Item -ItemType Directory -Path $WallpaperDestDir -Force | Out-Null
            }

            $destFile = Join-Path $WallpaperDestDir $wallpaperFiles[0].Name
            Copy-Item -LiteralPath $wallpaperFiles[0].FullName -Destination $destFile -Force
            Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name Wallpaper -Value $destFile

            Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
            Write-Host "Wallpaper set."
        } catch {
            Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
            Write-Host "Failed to set wallpaper."
        }
    }
}

# Set lock screen.
$LockScreenSourceDir = Join-Path $StoreRootPath 'Windows Explorer\Lock screen'
$LockScreenDestDir = Join-Path $env:USERPROFILE 'Pictures\Lock screen'

if (-not (Test-Path -LiteralPath $LockScreenSourceDir)) {
    Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
    Write-Host "Skipped lock screen. Source directory not found."
} elseif (-not $IsElevated) {
    Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
    Write-Host "Skipped lock screen. Requires elevation."
} else {
    $lockScreenFiles = @(Get-ChildItem -LiteralPath $LockScreenSourceDir -File)

    if ($lockScreenFiles.Count -eq 0) {
        Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host "Skipped lock screen. No file found in store."
    } elseif ($lockScreenFiles.Count -gt 1) {
        Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host "Skipped lock screen. Multiple files found in store."
    } else {
        try {
            if (-not (Test-Path -LiteralPath $LockScreenDestDir)) {
                New-Item -ItemType Directory -Path $LockScreenDestDir -Force | Out-Null
            }

            $destFile = Join-Path $LockScreenDestDir $lockScreenFiles[0].Name
            Copy-Item -LiteralPath $lockScreenFiles[0].FullName -Destination $destFile -Force

            $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP'
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath -Name LockScreenImagePath -Value $destFile -Type String

            Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
            Write-Host "Lock screen set."
        } catch {
            Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
            Write-Host "Failed to set lock screen."
        }
    }
}

exit 0