<# -----------------------------------------------------------------------
Copy and Paste the following in Powershell as Administrator:
--------------------------------------------------------------------------
Set-ExecutionPolicy Unrestricted
iwr -useb https://christitus.com/win | iex
--------------------------------------------------------------------------#>
#Set-PSDebug -Trace 2
############################################################################################################################################################
<# Disable User Account Control (UAC) #>
############################################################################################################################################################
Write-Host "Disable UAC Notification"  -ForegroundColor Cyan
$UACValue = "0" # 0 = Never Notify
$UACKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
# Set the registry value
Set-ItemProperty -Path $UACKey -Name "ConsentPromptBehaviorAdmin" -Value $UACValue
Set-ItemProperty -Path $UACKey -Name "ConsentPromptBehaviorUser" -Value $UACValue
Set-ItemProperty -Path $UACKey -Name "EnableLUA" -Value "0"
Write-Host "Done." -ForegroundColor Green
############################################################################################################################################################
<# NVIDIA Profile #>
############################################################################################################################################################
$answer = Read-Host "Do you want to execute the NVIDIA Profile setup script? [Y/N]"

if ($answer -match '^[Yy]') {
    Write-Host "Setting NVIDIA Profile..." -ForegroundColor Cyan

    # Define URLs
    $zipUrl = "https://github.com/h3kt0rx/powershell/raw/refs/heads/main/cfg/nvidiaProfileInspector.zip"
    $configUrl = "https://github.com/h3kt0rx/powershell/raw/refs/heads/main/cfg/custom.nip"

    # Define temporary paths
    $tempDir = "$env:TEMP\nvidiaProfileInspector"
    $zipPath = "$tempDir\nvidiaProfileInspector.zip"
    $extractPath = "$tempDir\nvidiaProfileInspector"

    try {
        # Create the directory
        New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

        # Download the ZIP file
        Write-Host "Downloading NVIDIA Profile Inspector..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -ErrorAction Stop | Out-Null

        # Extract the ZIP file
        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force -ErrorAction Stop | Out-Null

        # Download the configuration file
        Write-Host "Downloading custom profile..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $configUrl -OutFile "$extractPath\custom.nip" -ErrorAction Stop | Out-Null

        # Run the command to import the profile silently
        Write-Host "Importing NVIDIA profile..." -ForegroundColor Yellow
        $process = Start-Process -FilePath "$extractPath\nvidiaProfileInspector.exe" `
                                 -ArgumentList "-silentImport `"$extractPath\custom.nip`"" `
                                 -PassThru
        $process.WaitForExit()

        Write-Host "Cleaning up..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force -Path $tempDir

        Write-Host "Setting up fr33thy settings" -ForegroundColor Green
        # turn on disable dynamic pstate
        $subkeys = Get-ChildItem -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" -Force -ErrorAction SilentlyContinue
        foreach($key in $subkeys){
        if ($key -notlike '*Configuration'){
        reg add "$key" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f | Out-Null
        }
        }

        # disable hdcp
        $subkeys = Get-ChildItem -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" -Force -ErrorAction SilentlyContinue
        foreach($key in $subkeys){
        if ($key -notlike '*Configuration'){
        reg add "$key" /v "RMHdcpKeyglobZero" /t REG_DWORD /d "1" /f | Out-Null
        }
        }

        # unblock drs files
        $path = "C:\ProgramData\NVIDIA Corporation\Drs"
        Get-ChildItem -Path $path -Recurse | Unblock-File

        # set physx to gpu
        cmd /c "reg add `"HKLM\System\ControlSet001\Services\nvlddmkm\Parameters\Global\NVTweak`" /v `"NvCplPhysxAuto`" /t REG_DWORD /d `"0`" /f >nul 2>&1"

        # enable developer settings
        cmd /c "reg add `"HKLM\System\ControlSet001\Services\nvlddmkm\Parameters\Global\NVTweak`" /v `"NvDevToolsVisible`" /t REG_DWORD /d `"1`" /f >nul 2>&1"

        # allow access to the gpu performance counters to all users
        $subkeys = Get-ChildItem -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" -Force -ErrorAction SilentlyContinue
        foreach($key in $subkeys){
        if ($key -notlike '*Configuration'){
        reg add "$key" /v "RmProfilingAdminOnly" /t REG_DWORD /d "0" /f | Out-Null
        }
        }
        cmd /c "reg add `"HKLM\System\ControlSet001\Services\nvlddmkm\Parameters\Global\NVTweak`" /v `"RmProfilingAdminOnly`" /t REG_DWORD /d `"0`" /f >nul 2>&1"

        # disable show notification tray icon
        cmd /c "reg add `"HKCU\Software\NVIDIA Corporation\NvTray`" /v `"StartOnLogin`" /t REG_DWORD /d `"0`" /f >nul 2>&1"

        # enable nvidia legacy sharpen
        cmd /c "reg add `"HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS`" /v `"EnableGR535`" /t REG_DWORD /d `"0`" /f >nul 2>&1"
        cmd /c "reg add `"HKLM\SYSTEM\ControlSet001\Services\nvlddmkm\Parameters\FTS`" /v `"EnableGR535`" /t REG_DWORD /d `"0`" /f >nul 2>&1"
        cmd /c "reg add `"HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters\FTS`" /v `"EnableGR535`" /t REG_DWORD /d `"0`" /f >nul 2>&1"

        # FUNCTION RUN AS TRUSTED INSTALLER for the next setting
        function Run-Trusted([String]$command) {
        try {
    	Stop-Service -Name TrustedInstaller -Force -ErrorAction Stop -WarningAction Stop
  		}
  		catch {
    	taskkill /im trustedinstaller.exe /f >$null
  		}
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='TrustedInstaller'"
        $DefaultBinPath = $service.PathName
  		$trustedInstallerPath = "$env:SystemRoot\servicing\TrustedInstaller.exe"
  		if ($DefaultBinPath -ne $trustedInstallerPath) {
    	$DefaultBinPath = $trustedInstallerPath
  		}
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
        $base64Command = [Convert]::ToBase64String($bytes)
        sc.exe config TrustedInstaller binPath= "cmd.exe /c powershell.exe -encodedcommand $base64Command" | Out-Null
        sc.exe start TrustedInstaller | Out-Null
        sc.exe config TrustedInstaller binpath= "`"$DefaultBinPath`"" | Out-Null
        try {
    	Stop-Service -Name TrustedInstaller -Force -ErrorAction Stop -WarningAction Stop
  		}
  		catch {
    	taskkill /im trustedinstaller.exe /f >$null
  		}
        }
        # turn on override the scaling mode set by games and programs for all displays
        # perform scaling on display
        $configKeys = Get-ChildItem -Path "HKLM:\System\ControlSet001\Control\GraphicsDrivers\Configuration" -Recurse -ErrorAction SilentlyContinue
        foreach ($key in $configKeys) {
        $scalingValue = Get-ItemProperty -Path $key.PSPath -Name "Scaling" -ErrorAction SilentlyContinue
        if ($scalingValue) {
        $regPath = $key.PSPath.Replace('Microsoft.PowerShell.Core\Registry::', '').Replace('HKEY_LOCAL_MACHINE', 'HKLM')
        Run-Trusted -command "reg add `"$regPath`" /v `"Scaling`" /t REG_DWORD /d `"2`" /f"
        }
}

# turn on override the scaling mode set by games and programs for all displays
# perform scaling on display
$displayDbPath = "HKLM:\System\ControlSet001\Services\nvlddmkm\State\DisplayDatabase"
if (Test-Path $displayDbPath) {
$displays = Get-ChildItem -Path $displayDbPath -ErrorAction SilentlyContinue
foreach ($display in $displays) {
$regPath = $display.PSPath.Replace('Microsoft.PowerShell.Core\Registry::', '').Replace('HKEY_LOCAL_MACHINE', 'HKLM')
Run-Trusted -command "reg add `"$regPath`" /v `"ScalingConfig`" /t REG_BINARY /d `"DB02000010000000200100000E010000`" /f"
}
}
    }
    catch {
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }
}
else {
    Write-Host "Operation cancelled by user." -ForegroundColor DarkGray
}

############################################################################################################################################################
<# Script to Disable Core Isolation and Enable Game Mode #>
############################################################################################################################################################
$confirm1 = Read-Host "Do you want to enable Game Mode and disable Core Isolation? (Y/N)"
if ($confirm1 -match '^[Yy]$') {
    Write-Host "Enabling Game Mode and Disabling Core Isolation" -ForegroundColor Cyan

    # Enable Game Mode using reg add
    reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 1 /f
    reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v UseGameMode /t REG_DWORD /d 1 /f

    # Disable Core Isolation Memory Integrity using reg add
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f

    Write-Host "Done." -ForegroundColor Green
} else {
    Write-Host "Skipped Game Mode / Core Isolation changes." -ForegroundColor Yellow
}
############################################################################################################################################################
<# Run O&O ShutUp #>
############################################################################################################################################################
$confirm2 = Read-Host "Do you want to download and run O&O ShutUp 10? (Y/N)"
if ($confirm2 -match '^[Yy]$') {
    Write-Host "Running O&O ShutUp" -ForegroundColor Cyan

    $OOSU_filepath = "$ENV:temp\OOSU10.exe"
    $oosu_config = "$ENV:temp\ooshutup10.cfg"

    Invoke-WebRequest -Uri "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -OutFile $OOSU_filepath
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/h3kt0rx/powershell/refs/heads/main/cfg/ooshutup10.cfg" -OutFile $oosu_config

    Write-Host "Applying personal O&O Shutup 10 Policies"
    Start-Process $OOSU_filepath -ArgumentList "$oosu_config /quiet" -Wait

    Write-Host "Done." -ForegroundColor Green
} else {
    Write-Host "Skipped O&O ShutUp." -ForegroundColor Yellow
}
#---------------------------
# FASTER SHUTDOWN TWEAKS
#---------------------------
Write-Host "Running Registry Tweaks for Faster Shutdown" -ForegroundColor Cyan
# Force hung apps to close faster
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
# Set hung app timeout
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
# Set wait-to-kill time for user apps
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "1000" /f
# Set wait-to-kill time for services
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f
Write-Host "Done." -ForegroundColor Green

#-------
# MOUSE
#-------
Write-Host "Running Registry Tweaks for Mouse" -ForegroundColor Cyan
# Disable Enhance Pointer Precision
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f


# Mouse fix settings
reg add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d 0000000000000000c0cc0c0000000000809919000000000406626000000000 /f
reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d 0000000000000000000038000000000000007000000000000000a80000000000e0000000000000 /f
Write-Host "Done." -ForegroundColor Green


############################################################################################################################################################
<# Run Titus Script #>
############################################################################################################################################################
# PowerShell script to prompt before running commands
$command1 = 'iex "& { $(irm https://christitus.com/win) } -Config https://raw.githubusercontent.com/h3kt0rx/powershell/refs/heads/main/cfg/winutil.json -Run"'
$command2 = "iwr -useb 'https://christitus.com/win' | iex"

Write-Host "Available commands for CTT WinUtil:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Automated Custom Config" -ForegroundColor Cyan
Write-Host ""
Write-Host "2. Standard WinUtil" -ForegroundColor Cyan
Write-Host ""

$choice = Read-Host "Which command do you want to run? (1, 2, or N to cancel)"

switch ($choice) {
    {$_ -in '1'} {
        Write-Host "Opening new PowerShell window to execute command 1..." -ForegroundColor Green
        Start-Process powershell -ArgumentList "-NoExit", "-Command", $command1
    }
    {$_ -in '2'} {
        Write-Host "Opening new PowerShell window to execute command 2..." -ForegroundColor Green
        Start-Process powershell -ArgumentList "-NoExit", "-Command", $command2
    }
    default {
        Write-Host "Operation cancelled." -ForegroundColor Red
    }
}
