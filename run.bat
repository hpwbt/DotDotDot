@echo off
setlocal
set "SCRIPTS_DIR_PATH=%~dp0scripts"

rem Set UTF-8 code page.
chcp 65001 >nul 2>&1

rem Display banner.
<nul set /p ="______      _      _    _____ " & echo.
<nul set /p ="|  _  \    | |  /\| |/\|____ |" & echo.
<nul set /p ="| | | |___ | |_ \ ` ' /    / /" & echo.
<nul set /p ="| | | / _ \| __|_     _|   \ \" & echo.
<nul set /p ="| |/ / (_) | |_ / , . \.___/ /" & echo.
<nul set /p ="|___/ \___/ \__|\/|_|\/\____/ " & echo.

rem Set execution policy to Bypass for CurrentUser.
powershell -NoProfile -Command "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force" >nul 2>&1

rem Verify scripts exist.
if not exist "%SCRIPTS_DIR_PATH%\set-environment.ps1" (
    powershell -NoProfile -Command "Write-Host 'ERROR: ' -ForegroundColor Red -NoNewline; Write-Host 'set-environment.ps1 not found.'"
    pause
    exit /b 1
)

if not exist "%SCRIPTS_DIR_PATH%\apply.ps1" (
    powershell -NoProfile -Command "Write-Host 'ERROR: ' -ForegroundColor Red -NoNewline; Write-Host 'apply.ps1 not found.'"
    pause
    exit /b 1
)

rem Execute PowerShell scripts with proper error handling.
powershell -NoProfile -Command ^
    "$ErrorActionPreference='Stop'; try { & '%SCRIPTS_DIR_PATH%\set-environment.ps1'; & '%SCRIPTS_DIR_PATH%\apply.ps1' } catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 1 }"

if errorlevel 1 (
    powershell -NoProfile -Command "Write-Host \"`nERROR: \" -ForegroundColor Red -NoNewline; Write-Host \"One or more steps failed.\""
) else (
    powershell -NoProfile -Command "Write-Host \"`nSUCCESS: \" -ForegroundColor Green -NoNewline; Write-Host \"All steps succeeded.\""
)

pause
endlocal