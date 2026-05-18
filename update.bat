@echo off
setlocal
cd /d "%~dp0"

echo ============================================
echo  Uplinx Meta Manager - Update
echo ============================================
echo.
echo This will download the latest version from GitHub.
echo Your .env file and database will NOT be changed.
echo.
pause

echo Downloading latest version...
curl -L -o _update_tmp.zip "https://github.com/uplinxmarketing/ad-upload/archive/refs/heads/main.zip"
if errorlevel 1 (
    echo.
    echo ERROR: Download failed. Check your internet connection.
    pause
    exit /b 1
)

echo Extracting...
powershell -NoProfile -Command ^
  "Expand-Archive -Force '_update_tmp.zip' '_update_dir'"
if errorlevel 1 (
    echo ERROR: Extraction failed.
    del _update_tmp.zip 2>nul
    pause
    exit /b 1
)

echo Applying update (preserving .env and database)...
powershell -NoProfile -Command ^
  "Get-ChildItem '_update_dir\ad-upload-main' | Where-Object { $_.Name -notin @('.env','uplinx.db','update.bat') } | Copy-Item -Destination '.' -Recurse -Force"

echo Cleaning up...
rmdir /S /Q _update_dir 2>nul
del _update_tmp.zip 2>nul

echo.
echo ============================================
echo  Update complete!
echo  Restart start.bat to apply changes.
echo ============================================
pause
