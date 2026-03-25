<# -----------------------------------------------------------------------
Copy and Paste the following in Powershell as Administrator:
--------------------------------------------------------------------------
Set-ExecutionPolicy Unrestricted
iwr -useb https://christitus.com/win | iex
--------------------------------------------------------------------------#>

#region ── Functions ────────────────────────────────────────────────────────────

function Run-Trusted([String]$command) {
    try {
        Stop-Service -Name TrustedInstaller -Force -ErrorAction Stop -WarningAction Stop
    } catch {
        taskkill /im trustedinstaller.exe /f >$null
    }
    $service        = Get-CimInstance -ClassName Win32_Service -Filter "Name='TrustedInstaller'"
    $DefaultBinPath = $service.PathName
    $trustedInstallerPath = "$env:SystemRoot\servicing\TrustedInstaller.exe"
    if ($DefaultBinPath -ne $trustedInstallerPath) { $DefaultBinPath = $trustedInstallerPath }
    $bytes         = [System.Text.Encoding]::Unicode.GetBytes($command)
    $base64Command = [Convert]::ToBase64String($bytes)
    sc.exe config TrustedInstaller binPath= "cmd.exe /c powershell.exe -encodedcommand $base64Command" | Out-Null
    sc.exe start  TrustedInstaller | Out-Null
    sc.exe config TrustedInstaller binpath= "`"$DefaultBinPath`"" | Out-Null
    try {
        Stop-Service -Name TrustedInstaller -Force -ErrorAction Stop -WarningAction Stop
    } catch {
        taskkill /im trustedinstaller.exe /f >$null
    }
}

function Show-Menu {
    Clear-Host
    Write-Host "==========================================" -ForegroundColor DarkCyan
    Write-Host "         Windows Settings Menu            " -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  1  " -NoNewline -ForegroundColor Yellow; Write-Host "Windows Tweaks  " -NoNewline; Write-Host "(UAC, Game Mode, Shutdown, Mouse)" -ForegroundColor DarkGray
    Write-Host "  2  " -NoNewline -ForegroundColor Yellow; Write-Host "NVIDIA Profile Setup"
    Write-Host "  3  " -NoNewline -ForegroundColor Yellow; Write-Host "O&O ShutUp 10"
    Write-Host "  4  " -NoNewline -ForegroundColor Yellow; Write-Host "CTT WinUtil"
    Write-Host "  5  " -NoNewline -ForegroundColor Yellow; Write-Host "Run ALL"
    Write-Host ""
    Write-Host "  X  " -NoNewline -ForegroundColor Red;    Write-Host "Exit"
    Write-Host ""
}

function Pause-Menu {
    Write-Host ""
    Write-Host "Press any key to return to the menu..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

#endregion

#region ── Menu Actions ─────────────────────────────────────────────────────────

function Invoke-DisableUAC {
    Write-Host ""
    Write-Host "Disabling UAC Notification..." -ForegroundColor Cyan
    $UACKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-ItemProperty -Path $UACKey -Name "ConsentPromptBehaviorAdmin" -Value 0
    Set-ItemProperty -Path $UACKey -Name "ConsentPromptBehaviorUser"  -Value 0
    Set-ItemProperty -Path $UACKey -Name "EnableLUA"                  -Value 0
    Write-Host "Done." -ForegroundColor Green
}

function Invoke-NvidiaProfile {
    Write-Host ""
    Write-Host "Setting NVIDIA Profile..." -ForegroundColor Cyan

    $zipUrl    = "https://github.com/h3kt0rx/powershell/raw/refs/heads/main/cfg/nvidiaProfileInspector.zip"
    $configUrl = "https://github.com/h3kt0rx/powershell/raw/refs/heads/main/cfg/custom.nip"
    $tempDir   = "$env:TEMP\nvidiaProfileInspector"
    $zipPath   = "$tempDir\nvidiaProfileInspector.zip"
    $extractPath = "$tempDir\nvidiaProfileInspector"

    try {
        New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

        Write-Host "Downloading NVIDIA Profile Inspector..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -ErrorAction Stop | Out-Null

        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force -ErrorAction Stop | Out-Null

        Write-Host "Downloading custom profile..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $configUrl -OutFile "$extractPath\custom.nip" -ErrorAction Stop | Out-Null

        Write-Host "Importing NVIDIA profile..." -ForegroundColor Yellow
        $process = Start-Process -FilePath "$extractPath\nvidiaProfileInspector.exe" `
                                 -ArgumentList "-silentImport `"$extractPath\custom.nip`"" `
                                 -PassThru
        $process.WaitForExit()

        Write-Host "Cleaning up..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force -Path $tempDir

        Write-Host "Applying fr33thy registry settings..." -ForegroundColor Green

        $nvidiaClass = "Registry::HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"

        # Disable Dynamic PState
        foreach ($key in (Get-ChildItem -Path $nvidiaClass -Force -ErrorAction SilentlyContinue)) {
            if ($key -notlike '*Configuration') {
                reg add "$key" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f | Out-Null
            }
        }
        # Disable HDCP
        foreach ($key in (Get-ChildItem -Path $nvidiaClass -Force -ErrorAction SilentlyContinue)) {
            if ($key -notlike '*Configuration') {
                reg add "$key" /v "RMHdcpKeyglobZero" /t REG_DWORD /d "1" /f | Out-Null
            }
        }
        # Unblock DRS files
        Get-ChildItem -Path "C:\ProgramData\NVIDIA Corporation\Drs" -Recurse | Unblock-File

        # PhysX to GPU
        cmd /c "reg add `"HKLM\System\ControlSet001\Services\nvlddmkm\Parameters\Global\NVTweak`" /v `"NvCplPhysxAuto`" /t REG_DWORD /d `"0`" /f >nul 2>&1"

        # Enable developer settings
        cmd /c "reg add `"HKLM\System\ControlSet001\Services\nvlddmkm\Parameters\Global\NVTweak`" /v `"NvDevToolsVisible`" /t REG_DWORD /d `"1`" /f >nul 2>&1"

        # Allow GPU perf counters to all users
        foreach ($key in (Get-ChildItem -Path $nvidiaClass -Force -ErrorAction SilentlyContinue)) {
            if ($key -notlike '*Configuration') {
                reg add "$key" /v "RmProfilingAdminOnly" /t REG_DWORD /d "0" /f | Out-Null
            }
        }
        cmd /c "reg add `"HKLM\System\ControlSet001\Services\nvlddmkm\Parameters\Global\NVTweak`" /v `"RmProfilingAdminOnly`" /t REG_DWORD /d `"0`" /f >nul 2>&1"

        # Disable NVIDIA tray icon on login
        cmd /c "reg add `"HKCU\Software\NVIDIA Corporation\NvTray`" /v `"StartOnLogin`" /t REG_DWORD /d `"0`" /f >nul 2>&1"

        # Enable legacy sharpen
        cmd /c "reg add `"HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS`" /v `"EnableGR535`" /t REG_DWORD /d `"0`" /f >nul 2>&1"
        cmd /c "reg add `"HKLM\SYSTEM\ControlSet001\Services\nvlddmkm\Parameters\FTS`" /v `"EnableGR535`" /t REG_DWORD /d `"0`" /f >nul 2>&1"
        cmd /c "reg add `"HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters\FTS`" /v `"EnableGR535`" /t REG_DWORD /d `"0`" /f >nul 2>&1"

        # Scaling: perform on display (TrustedInstaller)
        $configKeys = Get-ChildItem -Path "HKLM:\System\ControlSet001\Control\GraphicsDrivers\Configuration" -Recurse -ErrorAction SilentlyContinue
        foreach ($key in $configKeys) {
            $scalingValue = Get-ItemProperty -Path $key.PSPath -Name "Scaling" -ErrorAction SilentlyContinue
            if ($scalingValue) {
                $regPath = $key.PSPath.Replace('Microsoft.PowerShell.Core\Registry::', '').Replace('HKEY_LOCAL_MACHINE', 'HKLM')
                Run-Trusted -command "reg add `"$regPath`" /v `"Scaling`" /t REG_DWORD /d `"2`" /f"
            }
        }
        $displayDbPath = "HKLM:\System\ControlSet001\Services\nvlddmkm\State\DisplayDatabase"
        if (Test-Path $displayDbPath) {
            foreach ($display in (Get-ChildItem -Path $displayDbPath -ErrorAction SilentlyContinue)) {
                $regPath = $display.PSPath.Replace('Microsoft.PowerShell.Core\Registry::', '').Replace('HKEY_LOCAL_MACHINE', 'HKLM')
                Run-Trusted -command "reg add `"$regPath`" /v `"ScalingConfig`" /t REG_BINARY /d `"DB02000010000000200100000E010000`" /f"
            }
        }
		Restart-Service NVDisplay.ContainerLocalSystem -Force
        Write-Host "Done." -ForegroundColor Green
    } catch {
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }
}

function Invoke-GameModeCoreisolation {
    Write-Host ""
    Write-Host "Enabling Game Mode and Disabling Core Isolation..." -ForegroundColor Cyan
    reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 1 /f
    reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v UseGameMode /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f
    Write-Host "Done." -ForegroundColor Green
}

function Invoke-OOShutUp {
    Write-Host ""
    Write-Host "Downloading and Running O&O ShutUp 10..." -ForegroundColor Cyan
    $OOSU_filepath = "$ENV:temp\OOSU10.exe"
    $oosu_config   = "$ENV:temp\ooshutup10.cfg"
    Invoke-WebRequest -Uri "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -OutFile $OOSU_filepath
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/h3kt0rx/powershell/refs/heads/main/cfg/ooshutup10.cfg" -OutFile $oosu_config
    Write-Host "Applying personal O&O ShutUp 10 policies..."
    Start-Process $OOSU_filepath -ArgumentList "$oosu_config /quiet" -Wait
    Write-Host "Done." -ForegroundColor Green
}

function Invoke-ShutdownTweaks {
    Write-Host ""
    Write-Host "Applying Faster Shutdown Registry Tweaks..." -ForegroundColor Cyan
    reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks"          /t REG_SZ /d "1"    /f
    reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout"        /t REG_SZ /d "1000" /f
    reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout"  /t REG_SZ /d "1000" /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f
    Write-Host "Done." -ForegroundColor Green
}

function Invoke-MouseTweaks {
    Write-Host ""
    Write-Host "Applying Mouse Registry Tweaks..." -ForegroundColor Cyan
    reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed"      /t REG_SZ /d "0"  /f
    reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0"  /f
    reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0"  /f
    reg add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
    reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d 0000000000000000c0cc0c0000000000809919000000000406626000000000 /f
    reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d 0000000000000000000038000000000000007000000000000000a80000000000e0000000000000 /f
    Write-Host "Done." -ForegroundColor Green
}

function Invoke-WindowsTweaks {
    Invoke-DisableUAC
    Invoke-GameModeCoreisolation
    Invoke-ShutdownTweaks
    Invoke-MouseTweaks
}

function Invoke-CTTWinUtil {
    Write-Host ""
    Write-Host "CTT WinUtil Options:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  1  " -NoNewline -ForegroundColor Cyan; Write-Host "Automated Custom Config"
    Write-Host "  2  " -NoNewline -ForegroundColor Cyan; Write-Host "Standard WinUtil"
    Write-Host "  N  " -NoNewline -ForegroundColor DarkGray; Write-Host "Cancel"
    Write-Host ""

    $command1 = 'iex "& { $(irm https://christitus.com/win) } -Config https://raw.githubusercontent.com/h3kt0rx/powershell/refs/heads/main/cfg/winutil.json -Run"'
    $command2 = "iwr -useb 'https://christitus.com/win' | iex"

    $choice = Read-Host "Choice"
    switch ($choice) {
        '1' {
            Write-Host "Opening new PowerShell window for Automated Custom Config..." -ForegroundColor Green
            Start-Process powershell -ArgumentList "-NoExit", "-Command", $command1
        }
        '2' {
            Write-Host "Opening new PowerShell window for Standard WinUtil..." -ForegroundColor Green
            Start-Process powershell -ArgumentList "-NoExit", "-Command", $command2
        }
        default {
            Write-Host "Cancelled." -ForegroundColor DarkGray
        }
    }
}

#endregion

#region ── Main Loop ────────────────────────────────────────────────────────────

do {
    Show-Menu
    $selection = Read-Host "Enter option"

    switch ($selection.ToUpper()) {
        '1' { Invoke-WindowsTweaks;  Pause-Menu }
        '2' { Invoke-NvidiaProfile;  Pause-Menu }
        '3' { Invoke-OOShutUp;       Pause-Menu }
        '4' { Invoke-CTTWinUtil;     Pause-Menu }
        '5' {
            Invoke-WindowsTweaks
            Invoke-NvidiaProfile
            Invoke-OOShutUp
            Invoke-CTTWinUtil
            Pause-Menu
        }
        'X' { Write-Host "`nExiting. Goodbye!`n" -ForegroundColor DarkCyan }
        default {
            Write-Host "`nInvalid option. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} while ($selection.ToUpper() -ne 'X')

#endregion
