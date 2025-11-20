@echo off
setlocal
set "SCRIPTS_DIR_PATH=%~dp0scripts"

rem Set UTF-8 code page.
chcp 65001 >nul 2>&1

rem Set execution policy to Bypass for CurrentUser.
powershell -NoProfile -Command "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force" >nul 2>&1

rem Display banner.
<nul set /p ="______      _      _    _____ " & echo.
<nul set /p ="|  _  \    | |  /\| |/\|____ |" & echo.
<nul set /p ="| | | |___ | |_ \ ` ' /    / /" & echo.
<nul set /p ="| | | / _ \| __|_     _|   \ \" & echo.
<nul set /p ="| |/ / (_) | |_ / , . \.___/ /" & echo.
<nul set /p ="|___/ \___/ \__|\/|_|\/\____/ " & echo.

rem Verify scripts exist.
if not exist "%SCRIPTS_DIR_PATH%\VerifySystemActivation.ps1" (
    powershell -NoProfile -Command "Write-Host 'ERROR: ' -ForegroundColor Red -NoNewline; Write-Host 'VerifySystemActivation.ps1 not found.'"
    pause
    exit /b 1
)
if not exist "%SCRIPTS_DIR_PATH%\UpdateWinget.ps1" (
    powershell -NoProfile -Command "Write-Host 'ERROR: ' -ForegroundColor Red -NoNewline; Write-Host 'UpdateWinget.ps1 not found.'"
    pause
    exit /b 1
)
if not exist "%SCRIPTS_DIR_PATH%\SetEnvironmentVariables.ps1" (
    powershell -NoProfile -Command "Write-Host 'ERROR: ' -ForegroundColor Red -NoNewline; Write-Host 'SetEnvironmentVariables.ps1 not found.'"
    pause
    exit /b 1
)
if not exist "%SCRIPTS_DIR_PATH%\ApplyBackgrounds.ps1" (
    powershell -NoProfile -Command "Write-Host 'ERROR: ' -ForegroundColor Red -NoNewline; Write-Host 'ApplyBackgrounds.ps1 not found.'"
    pause
    exit /b 1
)
if not exist "%SCRIPTS_DIR_PATH%\ApplyDotfiles.ps1" (
    powershell -NoProfile -Command "Write-Host 'ERROR: ' -ForegroundColor Red -NoNewline; Write-Host 'ApplyDotfiles.ps1 not found.'"
    pause
    exit /b 1
)
if not exist "%SCRIPTS_DIR_PATH%\CleanUpDesktopAndTaskbar.ps1" (
    powershell -NoProfile -Command "Write-Host 'ERROR: ' -ForegroundColor Red -NoNewline; Write-Host 'CleanUpDesktopAndTaskbar.ps1 not found.'"
    pause
    exit /b 1
)

rem Execute VerifySystemActivation script.
powershell -NoProfile -File "%SCRIPTS_DIR_PATH%\VerifySystemActivation.ps1"
if errorlevel 1 (
    powershell -NoProfile -Command "Write-Host"
    pause
    exit /b 1
)

rem Execute UpdateWinget script.
powershell -NoProfile -File "%SCRIPTS_DIR_PATH%\UpdateWinget.ps1"
if errorlevel 1 (
    powershell -NoProfile -Command "Write-Host"
    pause
    exit /b 1
)

rem Execute SetEnvironmentVariables script.
powershell -NoProfile -File "%SCRIPTS_DIR_PATH%\SetEnvironmentVariables.ps1"
if errorlevel 1 (
    powershell -NoProfile -Command "Write-Host"
    pause
    exit /b 1
)

rem Execute ApplyBackgrounds script.
powershell -NoProfile -File "%SCRIPTS_DIR_PATH%\ApplyBackgrounds.ps1"
if errorlevel 1 (
    powershell -NoProfile -Command "Write-Host"
    pause
    exit /b 1
)

rem Execute ApplyDotfiles script.
powershell -NoProfile -File "%SCRIPTS_DIR_PATH%\ApplyDotfiles.ps1"
if errorlevel 1 (
    powershell -NoProfile -Command "Write-Host"
    pause
    exit /b 1
)

rem Execute CleanUpDesktopAndTaskbar script.
powershell -NoProfile -File "%SCRIPTS_DIR_PATH%\CleanUpDesktopAndTaskbar.ps1"
if errorlevel 1 (
    powershell -NoProfile -Command "Write-Host"
    pause
    exit /b 1
)

rem Display success message.
powershell -NoProfile -Command "Write-Host \"`nSUMMARY: \" -ForegroundColor DarkCyan -NoNewline; Write-Host 'Tasks finished.'"
powershell -NoProfile -Command "Write-Host"
<nul set /p ="Press any key to restart . . ."
pause >nul

rem Restart computer.
shutdown /r /t 0

endlocal