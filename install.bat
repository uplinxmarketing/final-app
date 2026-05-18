@echo off
setlocal
cd /d "%~dp0"

set LOGFILE=%~dp0install_error.log
echo Uplinx Installer Log > "%LOGFILE%"
echo Started: %DATE% %TIME% >> "%LOGFILE%"
echo. >> "%LOGFILE%"

REM Unblock the PS1 file (Windows marks downloaded files as unsafe)
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
  "Unblock-File -Path '%~dp0installer.ps1' -ErrorAction SilentlyContinue"

REM Check PowerShell version and log it
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
  "$v = $PSVersionTable.PSVersion; 'PowerShell version: ' + $v" >> "%LOGFILE%" 2>&1

REM Run the GUI installer; capture all output and errors to log
powershell.exe -NoProfile -ExecutionPolicy Bypass -Sta ^
  -File "%~dp0installer.ps1" >> "%LOGFILE%" 2>&1

if errorlevel 1 (
    echo.
    echo  =====================================================
    echo   INSTALLER CRASHED
    echo  =====================================================
    echo.
    echo  An error log has been saved to:
    echo    %LOGFILE%
    echo.
    echo  Please send that file to support.
    echo.
    pause
)

endlocal
