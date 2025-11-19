Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Display setting message.
Write-Host "`nINFO: " -ForegroundColor Cyan -NoNewline
Write-Host "Setting wallpaper and lock screen . . ."

# Resolve paths from script location.
$ScriptDirPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$DotfilesRootPath = Split-Path $ScriptDirPath -Parent
$StoreRootPath = Join-Path $DotfilesRootPath 'store'

# Verify we're running from inside %USERPROFILE%\Dotfiles.
$ExpectedDirPath = Join-Path $env:USERPROFILE 'Dotfiles'
if ($DotfilesRootPath -ne $ExpectedDirPath) {
    Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
    Write-Host ("This script must be run in '{0}'. Currently it's running in '{1}'." -f $ExpectedDirPath, $DotfilesRootPath)
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

# Define source and destination paths.
$WallpaperSourceDir = Join-Path $StoreRootPath 'Windows Explorer\Wallpaper'
$LockScreenSourceDir = Join-Path $StoreRootPath 'Windows Explorer\Lock screen'
$WallpaperDestDir = Join-Path $env:USERPROFILE 'Pictures\Wallpaper'
$LockScreenDestDir = Join-Path $env:USERPROFILE 'Pictures\Lock screen'

# Set wallpaper.
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
            # Create destination directory if needed.
            if (-not (Test-Path -LiteralPath $WallpaperDestDir)) {
                New-Item -ItemType Directory -Path $WallpaperDestDir -Force | Out-Null
            }

            # Copy file to destination.
            $sourceFile = $wallpaperFiles[0]
            $destFile = Join-Path $WallpaperDestDir $sourceFile.Name
            Copy-Item -LiteralPath $sourceFile.FullName -Destination $destFile -Force

            # Set wallpaper via registry.
            Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name Wallpaper -Value $destFile
            Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name WallpaperStyle -Value '10'

            Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
            Write-Host "Wallpaper set."
        } catch {
            Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
            Write-Host "Failed to set wallpaper."
        }
    }
}

# Set lock screen.
if (-not (Test-Path -LiteralPath $LockScreenSourceDir)) {
    Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
    Write-Host "Skipped lock screen. Source directory not found."
} else {
    $lockScreenFiles = @(Get-ChildItem -LiteralPath $LockScreenSourceDir -File)

    if ($lockScreenFiles.Count -eq 0) {
        Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host "Skipped lock screen. No file found in store."
    } elseif ($lockScreenFiles.Count -gt 1) {
        Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host "Skipped lock screen. Multiple files found in store."
    } else {
        if (-not $IsElevated) {
            Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
            Write-Host "Skipped lock screen. Requires elevation."
        } else {
            try {
                # Create destination directory if needed.
                if (-not (Test-Path -LiteralPath $LockScreenDestDir)) {
                    New-Item -ItemType Directory -Path $LockScreenDestDir -Force | Out-Null
                }

                # Copy file to destination.
                $sourceFile = $lockScreenFiles[0]
                $destFile = Join-Path $LockScreenDestDir $sourceFile.Name
                Copy-Item -LiteralPath $sourceFile.FullName -Destination $destFile -Force

                # Set lock screen via system-level registry.
                $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP'
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }

                Set-ItemProperty -Path $regPath -Name LockScreenImagePath -Value $destFile -Type String
                Set-ItemProperty -Path $regPath -Name LockScreenImageStatus -Value 1 -Type DWord

                Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
                Write-Host "Lock screen set."
            } catch {
                Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
                Write-Host "Failed to set lock screen."
            }
        }
    }
}

exit 0