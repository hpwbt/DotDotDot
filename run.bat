@echo off
setlocal
set "SCRIPTS=%~dp0scripts"

rem Set UTF-8 code page.
chcp 65001 >nul 2>&1

rem Display banner.
<nul set /p ="______      _      _    _____ " & echo.
<nul set /p ="|  _  \    | |  /\| |/\|____ |" & echo.
<nul set /p ="| | | |___ | |_ \ ` ' /    / /" & echo.
<nul set /p ="| | | / _ \| __|_     _|   \ \" & echo.
<nul set /p ="| |/ / (_) | |_ / , . \.___/ /" & echo.
<nul set /p ="|___/ \___/ \__|\/|_|\/\____/ " & echo.

rem Verify scripts exist.
if not exist "%SCRIPTS%\env.ps1" (
    powershell -NoProfile -Command "Write-Host 'Error: env.ps1 not found' -ForegroundColor Red"
    pause
    exit /b 1
)
if not exist "%SCRIPTS%\apply.ps1" (
    powershell -NoProfile -Command "Write-Host 'Error: apply.ps1 not found' -ForegroundColor Red"
    pause
    exit /b 1
)

rem Execute PowerShell scripts with proper error handling.
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ErrorActionPreference='Stop'; try { & '%SCRIPTS%\env.ps1'; & '%SCRIPTS%\apply.ps1' } catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 1 }"

if errorlevel 1 (
    powershell -NoProfile -Command "Write-Host \"`nOne or more steps failed.\" -ForegroundColor Red"
) else (
    powershell -NoProfile -Command "Write-Host \"`nAll steps succeeded.\" -ForegroundColor Green"
)

pause
endlocal