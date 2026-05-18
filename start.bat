@echo off
setlocal enabledelayedexpansion
title Uplinx Meta Manager
color 0A

REM Always run from the app folder
cd /d "%~dp0"

echo.
echo  ============================================
echo   UPLINX META MANAGER
echo  ============================================
echo.

REM ── Check venv exists ────────────────────────────────────────────────────
if not exist venv\Scripts\python.exe (
    echo  ERROR: App is not installed yet.
    echo.
    echo  Please run install.bat first.
    echo.
    pause
    exit /b 1
)

REM ── Check .env exists ────────────────────────────────────────────────────
if not exist .env (
    echo  ERROR: .env file not found.
    echo.
    echo  Please run install.bat first.
    echo.
    pause
    exit /b 1
)

REM ── Ensure all packages are up to date ───────────────────────────────────
echo  Checking packages...
venv\Scripts\pip install -r requirements.txt -q --no-warn-script-location
echo  OK
echo.

REM ── Find a free port using Python (reliable on all Windows versions) ──────
for /f %%P in ('venv\Scripts\python find_port.py') do set PORT=%%P
if "%PORT%"=="" set PORT=8000

echo  Starting server at http://localhost:%PORT%
echo  Press Ctrl+C to stop.
echo.
echo  Opening browser in 5 seconds...
echo  If it does not open, visit: http://localhost:%PORT%
echo.

REM Open browser after 5 seconds
start "" /b cmd /c "timeout /t 5 /nobreak >nul 2>&1 && start http://localhost:%PORT%"

REM Start the server
venv\Scripts\uvicorn main:app --host 0.0.0.0 --port %PORT%

echo.
echo  Server stopped.
echo.
pause
endlocal
