<#
.SYNOPSIS
    Uplinx Meta Manager - Windows Installer
.DESCRIPTION
    GUI installer: choose directory -> progress bar -> launch.
    Run via install.bat (passes -Sta and logs to install_error.log).
#>

# -- Logging (from line 1) ----------------------------------------------------
$LogFile = Join-Path $PSScriptRoot "install_error.log"
function Write-Log($msg) {
    $line = "$(Get-Date -Format 'HH:mm:ss')  $msg"
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
    Write-Output $line
}

Write-Log "installer.ps1 started"
Write-Log ("PSVersion: " + $PSVersionTable.PSVersion)
Write-Log ("OS: " + [System.Environment]::OSVersion.VersionString)
Write-Log ("STA: " + [System.Threading.Thread]::CurrentThread.ApartmentState)
Write-Log ("ScriptRoot: " + $PSScriptRoot)

# -- Load Windows Forms -------------------------------------------------------
Write-Log "Loading Windows Forms..."
try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Write-Log "Windows Forms loaded OK"
} catch {
    Write-Log ("FATAL: Could not load Windows Forms: " + $_)
    exit 1
}

# -- Config -------------------------------------------------------------------
$AppName   = "Uplinx Meta Manager"
$GithubZip = "https://github.com/uplinxmarketing/ad-upload/archive/refs/heads/main.zip"
$DefaultDir = "$env:LOCALAPPDATA\Uplinx"

Write-Log ("DefaultDir: " + $DefaultDir)

# -- Colours ------------------------------------------------------------------
$bgDark   = [System.Drawing.Color]::FromArgb(13,13,20)
$accent   = [System.Drawing.Color]::FromArgb(108,99,255)
$txtLight = [System.Drawing.Color]::FromArgb(232,232,240)
$txtDim   = [System.Drawing.Color]::FromArgb(96,96,128)

# -- UI helpers ---------------------------------------------------------------
function New-Panel {
    $p = New-Object System.Windows.Forms.Panel
    $p.Dock      = "Fill"
    $p.BackColor = $bgDark
    $p.Visible   = $false
    $form.Controls.Add($p)
    $p
}
function New-Lbl($text, $x, $y, $w, $h, $size=10, $bold=$false, $color=$null) {
    $l = New-Object System.Windows.Forms.Label
    $l.Text      = $text
    $l.Location  = New-Object System.Drawing.Point($x,$y)
    $l.Size      = New-Object System.Drawing.Size($w,$h)
    $l.Font      = New-Object System.Drawing.Font("Segoe UI", $size, $(if($bold){"Bold"}else{"Regular"}))
    $l.ForeColor = if($color){$color}else{$txtLight}
    $l
}
function New-Btn($text, $x, $y, $w=120, $h=38) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text      = $text
    $b.Location  = New-Object System.Drawing.Point($x,$y)
    $b.Size      = New-Object System.Drawing.Size($w,$h)
    $b.FlatStyle = "Flat"
    $b.BackColor = $accent
    $b.ForeColor = [System.Drawing.Color]::White
    $b.Font      = New-Object System.Drawing.Font("Segoe UI", 10, "Bold")
    $b.FlatAppearance.BorderSize = 0
    $b.Cursor    = [System.Windows.Forms.Cursors]::Hand
    $b
}
function Step($msg, $pct, $detail="") {
    Write-Log ($msg + " (" + $pct + "pct)")
    $script:lblStep.Text = $msg
    $script:progBar.Value = [Math]::Min($pct, 100)
    if ($detail) { $script:lblLog.Text = $detail }
    [System.Windows.Forms.Application]::DoEvents()
}

# -- Build form ---------------------------------------------------------------
Write-Log "Building form..."
try {
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $form = New-Object System.Windows.Forms.Form
    $form.Text            = $AppName + " -- Installer"
    $form.Size            = New-Object System.Drawing.Size(520,380)
    $form.StartPosition   = "CenterScreen"
    $form.FormBorderStyle = "FixedSingle"
    $form.MaximizeBox     = $false
    $form.BackColor       = $bgDark
    $form.ForeColor       = $txtLight
    $form.Font            = New-Object System.Drawing.Font("Segoe UI", 10)
    Write-Log "Form created OK"
} catch {
    Write-Log ("FATAL: form creation failed: " + $_)
    [System.Windows.Forms.MessageBox]::Show(
        "Could not create installer window:`n`n" + $_ + "`n`nSee install_error.log.",
        "Uplinx Installer", "OK", "Error")
    exit 1
}

Write-Log "Building panels..."

# == Panel 1 - Welcome ========================================================
$pWelcome = New-Panel
$pWelcome.Visible = $true
$pWelcome.Controls.Add((New-Lbl $AppName 40 60 440 38 18 $true))
$pWelcome.Controls.Add((New-Lbl "AI-powered Meta advertising manager" 40 98 440 24 10 $false $txtDim))
$pWelcome.Controls.Add((New-Lbl "This installer will:" 40 150 440 24 10 $true))
$pWelcome.Controls.Add((New-Lbl "  * Download the latest version from GitHub" 40 175 440 22 10))
$pWelcome.Controls.Add((New-Lbl "  * Set up Python and all dependencies" 40 197 440 22 10))
$pWelcome.Controls.Add((New-Lbl "  * Create a launch shortcut on your Desktop" 40 219 440 22 10))
$pWelcome.Controls.Add((New-Lbl "Requirements: Windows 10+, Python 3.10+, internet" 40 265 440 20 9 $false $txtDim))
$btnNext = New-Btn "Next ->" 370 305
$pWelcome.Controls.Add($btnNext)
$btnNext.Add_Click({ $pWelcome.Visible=$false; $pDir.Visible=$true })

# == Panel 2 - Directory ======================================================
$pDir = New-Panel
$pDir.Controls.Add((New-Lbl "Choose Install Location" 40 50 440 32 16 $true))
$pDir.Controls.Add((New-Lbl "Select the folder where Uplinx will be installed:" 40 88 440 22 10 $false $txtDim))

$txtDir = New-Object System.Windows.Forms.TextBox
$txtDir.Location    = New-Object System.Drawing.Point(40,125)
$txtDir.Size        = New-Object System.Drawing.Size(330,30)
$txtDir.Text        = $DefaultDir
$txtDir.BackColor   = [System.Drawing.Color]::FromArgb(13,13,20)
$txtDir.ForeColor   = $txtLight
$txtDir.BorderStyle = "FixedSingle"
$txtDir.Font        = New-Object System.Drawing.Font("Segoe UI",10)
$pDir.Controls.Add($txtDir)

$btnBrowse = New-Object System.Windows.Forms.Button
$btnBrowse.Text      = "Browse..."
$btnBrowse.Location  = New-Object System.Drawing.Point(378,124)
$btnBrowse.Size      = New-Object System.Drawing.Size(88,32)
$btnBrowse.FlatStyle = "Flat"
$btnBrowse.BackColor = [System.Drawing.Color]::FromArgb(37,37,64)
$btnBrowse.ForeColor = $txtLight
$btnBrowse.Font      = New-Object System.Drawing.Font("Segoe UI",10)
$btnBrowse.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(37,37,64)
$pDir.Controls.Add($btnBrowse)
$btnBrowse.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description  = "Select install folder"
    $dlg.SelectedPath = $txtDir.Text
    if ($dlg.ShowDialog() -eq "OK") { $txtDir.Text = $dlg.SelectedPath }
})

$pDir.Controls.Add((New-Lbl "Disk space needed: ~200 MB" 40 168 440 20 9 $false $txtDim))

$chkDesktop = New-Object System.Windows.Forms.CheckBox
$chkDesktop.Text      = "Create Desktop shortcut"
$chkDesktop.Location  = New-Object System.Drawing.Point(40,210)
$chkDesktop.Size      = New-Object System.Drawing.Size(300,24)
$chkDesktop.Checked   = $true
$chkDesktop.ForeColor = $txtLight
$chkDesktop.Font      = New-Object System.Drawing.Font("Segoe UI",10)
$pDir.Controls.Add($chkDesktop)

$btnBack = New-Btn "<- Back" 240 305 110
$btnBack.BackColor = [System.Drawing.Color]::FromArgb(37,37,64)
$pDir.Controls.Add($btnBack)
$btnBack.Add_Click({ $pDir.Visible=$false; $pWelcome.Visible=$true })

$btnInstall = New-Btn "Install" 370 305
$pDir.Controls.Add($btnInstall)

# == Panel 3 - Progress =======================================================
$pProgress = New-Panel
$pProgress.Controls.Add((New-Lbl "Installing..." 40 50 440 32 16 $true))

$script:lblStep = New-Lbl "Starting..." 40 95 440 22 10 $false $txtDim
$pProgress.Controls.Add($script:lblStep)

$script:progBar = New-Object System.Windows.Forms.ProgressBar
$script:progBar.Location = New-Object System.Drawing.Point(40,130)
$script:progBar.Size     = New-Object System.Drawing.Size(430,22)
$script:progBar.Minimum  = 0
$script:progBar.Maximum  = 100
$script:progBar.Style    = "Continuous"
$pProgress.Controls.Add($script:progBar)

$script:lblLog = New-Lbl "" 40 165 430 120 9 $false $txtDim
$script:lblLog.AutoSize = $false
$pProgress.Controls.Add($script:lblLog)

# == Panel 4 - Finish =========================================================
$pFinish = New-Panel
$pFinish.Controls.Add((New-Lbl "Installation Complete!" 40 60 440 38 18 $true))
$pFinish.Controls.Add((New-Lbl "Uplinx Meta Manager is ready to use." 40 98 440 24 10 $false $txtDim))
$pFinish.Controls.Add((New-Lbl "Next steps:" 40 150 440 24 10 $true))
$pFinish.Controls.Add((New-Lbl "  1. Launch the app - it will open in your browser" 40 175 440 22 10))
$pFinish.Controls.Add((New-Lbl "  2. Enter your API keys in the Setup Wizard" 40 197 440 22 10))
$pFinish.Controls.Add((New-Lbl "  3. Paste your Meta access token to connect" 40 219 440 22 10))

$btnLaunch = New-Btn "Launch App" 260 305 160
$pFinish.Controls.Add($btnLaunch)
$btnLaunch.Add_Click({
    $startBat = Join-Path $script:InstallDir "start.bat"
    if (Test-Path $startBat) { Start-Process $startBat }
    else { [System.Windows.Forms.MessageBox]::Show("start.bat not found in " + $script:InstallDir) }
    $form.Close()
})
$btnClose = New-Btn "Close" 390 305 86
$btnClose.BackColor = [System.Drawing.Color]::FromArgb(37,37,64)
$pFinish.Controls.Add($btnClose)
$btnClose.Add_Click({ $form.Close() })

# == Install logic - runs synchronously on UI thread with DoEvents() ===========
$script:InstallDir = $DefaultDir

$btnInstall.Add_Click({
    $script:InstallDir = $txtDir.Text.Trim()
    $createShortcut    = $chkDesktop.Checked
    $pDir.Visible      = $false
    $pProgress.Visible = $true
    $btnInstall.Enabled = $false
    [System.Windows.Forms.Application]::DoEvents()

    Write-Log ("Install started -- dir=" + $script:InstallDir)

    try {
        # 1 -- Create directory
        Step "Creating install directory..." 5
        New-Item -ItemType Directory -Force -Path $script:InstallDir | Out-Null

        # 2 -- Download
        Step "Downloading from GitHub..." 10 $GithubZip
        $zipPath = Join-Path $env:TEMP "uplinx_install.zip"
        Invoke-WebRequest -Uri $GithubZip -OutFile $zipPath -UseBasicParsing

        # 3 -- Extract
        Step "Extracting files..." 40
        $tmpDir = Join-Path $env:TEMP "uplinx_extracted"
        if (Test-Path $tmpDir) { Remove-Item $tmpDir -Recurse -Force }
        Expand-Archive -Force $zipPath $tmpDir

        # 4 -- Copy files (preserve .env and DB if they exist)
        Step "Copying files..." 55
        $srcDir = Join-Path $tmpDir "ad-upload-main"
        Get-ChildItem $srcDir | Where-Object {
            $_.Name -notin @('.env','uplinx.db','update.bat')
        } | Copy-Item -Destination $script:InstallDir -Recurse -Force
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        Remove-Item $tmpDir  -Recurse -Force -ErrorAction SilentlyContinue

        # 5 -- Find Python
        Step "Locating Python..." 62
        $py = $null
        foreach ($cmd in @("py","python","python3")) {
            try {
                $ver = & $cmd --version 2>&1
                Write-Log ("Tried " + $cmd + " -> " + $ver)
                if ($ver -match "Python 3\.(1[0-9]|[89])") { $py = $cmd; break }
            } catch { Write-Log ("  skip " + $cmd + ": " + $_) }
        }
        if (-not $py) {
            throw "Python 3.10+ not found. Install from python.org and tick 'Add Python to PATH', then run install.bat again."
        }
        Write-Log ("Using Python: " + $py)

        # 6 -- Create venv
        Step "Creating virtual environment..." 70 ("Python: " + $py)
        $venvPath = Join-Path $script:InstallDir "venv"
        if (-not (Test-Path $venvPath)) {
            $r = & $py -m venv $venvPath 2>&1
            Write-Log ("venv: " + $r)
            if (-not (Test-Path (Join-Path $venvPath "Scripts\python.exe"))) {
                throw "Virtual environment creation failed. Try moving the install folder out of Downloads."
            }
        }

        # 7 -- Install packages
        Step "Installing packages (this may take 1-2 minutes)..." 78
        $pip = Join-Path $venvPath "Scripts\pip.exe"
        $req = Join-Path $script:InstallDir "requirements.txt"
        if (Test-Path $req) {
            $r = & $pip install -r $req --quiet 2>&1
            Write-Log ("pip: " + $r)
        }

        # 8 -- Create .env if missing
        Step "Setting up config..." 92
        $envFile = Join-Path $script:InstallDir ".env"
        if (-not (Test-Path $envFile)) {
            $envContent = "AI_PROVIDER=claude`nANTHROPIC_API_KEY=`nOPENAI_API_KEY=`nGROQ_API_KEY=`nMETA_APP_ID=`nMETA_APP_SECRET=`n"
            [System.IO.File]::WriteAllText($envFile, $envContent, [System.Text.Encoding]::UTF8)
            Write-Log ".env created"
        } else {
            Write-Log ".env already exists - preserved"
        }

        # 9 -- Desktop shortcut
        if ($createShortcut) {
            Step "Creating Desktop shortcut..." 97
            $startBat = Join-Path $script:InstallDir "start.bat"
            $lnkPath  = $env:USERPROFILE + "\Desktop\Uplinx Meta Manager.lnk"
            $wsh = New-Object -ComObject WScript.Shell
            $lnk = $wsh.CreateShortcut($lnkPath)
            $lnk.TargetPath       = $startBat
            $lnk.WorkingDirectory = $script:InstallDir
            $lnk.Description      = "Uplinx Meta Manager"
            $lnk.IconLocation     = "%SystemRoot%\System32\SHELL32.dll,14"
            $lnk.Save()
            Write-Log ("Shortcut -> " + $lnkPath)
        }

        Step "Done!" 100
        Write-Log "Installation complete"
        [System.Windows.Forms.Application]::DoEvents()

        $pProgress.Visible = $false
        $pFinish.Visible   = $true

    } catch {
        Write-Log ("INSTALL FAILED: " + $_)
        $pProgress.Visible = $false
        $pDir.Visible      = $true
        $btnInstall.Enabled = $true
        [System.Windows.Forms.MessageBox]::Show(
            "Installation failed:`n`n" + $_ + "`n`nSee install_error.log for full details.",
            "Uplinx Installer", "OK", "Error")
    }
})

Write-Log "Panels built -- showing form"

try {
    $form.ShowDialog() | Out-Null
    Write-Log "Form closed"
} catch {
    Write-Log ("FATAL: " + $_)
    [System.Windows.Forms.MessageBox]::Show(
        "Installer crashed:`n`n" + $_ + "`n`nSee install_error.log.",
        "Uplinx Installer", "OK", "Error")
}
