@echo off
setlocal
cd /d "%~dp0"

REM ── Check venv exists ────────────────────────────────────────────────────
if not exist venv\Scripts\pythonw.exe (
    echo ERROR: App is not installed yet. Please run install.bat first.
    pause
    exit /b 1
)

REM ── Check .env exists ────────────────────────────────────────────────────
if not exist .env (
    echo ERROR: .env file not found. Please run install.bat first.
    pause
    exit /b 1
)

REM ── Install / update packages silently ───────────────────────────────────
venv\Scripts\pip install -r requirements.txt -q --no-warn-script-location

REM ── Launch tray app (no console window) ──────────────────────────────────
start "" venv\Scripts\pythonw.exe tray.pyw

endlocal
