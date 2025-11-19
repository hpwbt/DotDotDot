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
if not exist "%SCRIPTS_DIR_PATH%\SetEnvironmentVariables.ps1" (
    powershell -NoProfile -Command "Write-Host 'ERROR: ' -ForegroundColor Red -NoNewline; Write-Host 'SetEnvironmentVariables.ps1 not found.'"
    pause
    exit /b 1
)
if not exist "%SCRIPTS_DIR_PATH%\ApplyPersonalizations.ps1" (
    powershell -NoProfile -Command "Write-Host 'ERROR: ' -ForegroundColor Red -NoNewline; Write-Host 'ApplyPersonalizations.ps1 not found.'"
    pause
    exit /b 1
)
if not exist "%SCRIPTS_DIR_PATH%\ApplySettings.ps1" (
    powershell -NoProfile -Command "Write-Host 'ERROR: ' -ForegroundColor Red -NoNewline; Write-Host 'ApplySettings.ps1 not found.'"
    pause
    exit /b 1
)

rem Execute VerifySystemActivation script.
powershell -NoProfile -File "%SCRIPTS_DIR_PATH%\VerifySystemActivation.ps1"
if errorlevel 1 (
    pause
    exit /b 1
)

rem Execute SetEnvironmentVariables script.
powershell -NoProfile -File "%SCRIPTS_DIR_PATH%\SetEnvironmentVariables.ps1"
if errorlevel 1 (
    pause
    exit /b 1
)

rem Execute ApplyPersonalizations script.
powershell -NoProfile -File "%SCRIPTS_DIR_PATH%\ApplyPersonalizations.ps1"
if errorlevel 1 (
    pause
    exit /b 1
)

rem Execute ApplySettings script.
powershell -NoProfile -File "%SCRIPTS_DIR_PATH%\ApplySettings.ps1"
if errorlevel 1 (
    pause
    exit /b 1
)

rem Display success message.
powershell -NoProfile -Command "Write-Host 'SUMMARY: ' -ForegroundColor DarkCyan -NoNewline; Write-Host 'Tasks finished.'"
powershell -NoProfile -Command "Write-Host"

pause
endlocal