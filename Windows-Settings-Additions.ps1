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
    Write-Host "  1  " -NoNewline -ForegroundColor Yellow; Write-Host "Run ALL (2-6) and Automated CTT"
    Write-Host "  2  " -NoNewline -ForegroundColor Yellow; Write-Host "Windows 11/LTSC Tweaks and Fixes"
    Write-Host "  3  " -NoNewline -ForegroundColor Yellow; Write-Host "NVIDIA Profile Setup"
    Write-Host "  4  " -NoNewline -ForegroundColor Yellow; Write-Host "O&O ShutUp 10"
    Write-Host "  5  " -NoNewline -ForegroundColor Yellow; Write-Host "CTT WinUtil Options"
    Write-Host "  6  " -NoNewline -ForegroundColor Yellow; Write-Host "Microsoft Activation Scripts (MAS)"
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

    New-Item -Path $UACKey -Force | Out-Null
    New-ItemProperty -Path $UACKey -Name "ConsentPromptBehaviorAdmin" -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $UACKey -Name "ConsentPromptBehaviorUser"  -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $UACKey -Name "EnableLUA"                  -PropertyType DWord -Value 0 -Force | Out-Null

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

        Write-Host "Applying Nvidia registry settings..." -ForegroundColor Green

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
    }
    catch {
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

    reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed"        /t REG_SZ /d "0"  /f
    reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1"   /t REG_SZ /d "0"  /f
    reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2"   /t REG_SZ /d "0"  /f
    reg add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
    reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d 0000000000000000c0cc0c0000000000809919000000000406626000000000 /f
    reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d 0000000000000000000038000000000000007000000000000000a80000000000e0000000000000 /f

    Write-Host "Done." -ForegroundColor Green
}

function Invoke-QuickAccessTweaks {
    Write-Host ""
    Write-Host "Disabling Quick Access Recent Files and Frequent Folders..." -ForegroundColor Cyan

    $ExplorerKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"

    # Create the registry key only if it does not already exist.
    if (-not (Test-Path -LiteralPath $ExplorerKey)) {
        New-Item -Path $ExplorerKey -ItemType Key -ErrorAction Stop | Out-Null
    }

    # Create the values if missing, otherwise update them.
    if ($null -eq (Get-ItemProperty -Path $ExplorerKey -Name "ShowRecent" -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path $ExplorerKey `
                         -Name "ShowRecent" `
                         -PropertyType DWord `
                         -Value 0 `
                         -ErrorAction Stop | Out-Null
    }
    else {
        Set-ItemProperty -Path $ExplorerKey `
                         -Name "ShowRecent" `
                         -Type DWord `
                         -Value 0 `
                         -ErrorAction Stop
    }

    if ($null -eq (Get-ItemProperty -Path $ExplorerKey -Name "ShowFrequent" -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path $ExplorerKey `
                         -Name "ShowFrequent" `
                         -PropertyType DWord `
                         -Value 0 `
                         -ErrorAction Stop | Out-Null
    }
    else {
        Set-ItemProperty -Path $ExplorerKey `
                         -Name "ShowFrequent" `
                         -Type DWord `
                         -Value 0 `
                         -ErrorAction Stop
    }

    # Clear the Quick Access history/cache Windows has already accumulated.
    $AutomaticDestinations = Join-Path $env:APPDATA "Microsoft\Windows\Recent\AutomaticDestinations"
    $CustomDestinations   = Join-Path $env:APPDATA "Microsoft\Windows\Recent\CustomDestinations"

    if (Test-Path -LiteralPath $AutomaticDestinations) {
        Remove-Item -Path (Join-Path $AutomaticDestinations "*") `
                    -Force `
                    -ErrorAction SilentlyContinue
    }

    # if (Test-Path -LiteralPath $CustomDestinations) {
    #     Remove-Item -Path (Join-Path $CustomDestinations "*") `
    #                 -Force `
    #                 -ErrorAction SilentlyContinue
    # }

    Write-Host "Done." -ForegroundColor Green
}


function Invoke-FileDeleteTweaks {
    Write-Host ""
    Write-Host "Disabling File Delete Confirmation..." -ForegroundColor Cyan

    $ExplorerAdvancedKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"

    # Create the registry key only if it genuinely does not exist.
    if (-not (Test-Path -LiteralPath $ExplorerAdvancedKey)) {
        New-Item -Path $ExplorerAdvancedKey -ItemType Key -ErrorAction Stop | Out-Null
    }

    # Create the value if missing, otherwise update the existing value.
    if ($null -eq (Get-ItemProperty -Path $ExplorerAdvancedKey `
                                      -Name "ConfirmFileDelete" `
                                      -ErrorAction SilentlyContinue)) {

        New-ItemProperty -Path $ExplorerAdvancedKey `
                         -Name "ConfirmFileDelete" `
                         -PropertyType DWord `
                         -Value 0 `
                         -ErrorAction Stop | Out-Null
    }
    else {
        Set-ItemProperty -Path $ExplorerAdvancedKey `
                         -Name "ConfirmFileDelete" `
                         -Type DWord `
                         -Value 0 `
                         -ErrorAction Stop
    }

    Write-Host "Done." -ForegroundColor Green
}

function Restart-Explorer {
    Write-Host ""
    Write-Host "Restarting Windows Explorer..." -ForegroundColor Cyan

    try {
        $explorerProcesses = Get-Process -Name explorer -ErrorAction SilentlyContinue

        if ($explorerProcesses) {
            $explorerProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 750
        }

        # Start Explorer only if it is not already running.
        if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) {
            Start-Process explorer.exe
        }

        Write-Host "Explorer restarted." -ForegroundColor Green
    }
    catch {
        Write-Host "Could not restart Explorer automatically: $_" -ForegroundColor Yellow
    }
}

function Invoke-WindowsTweaks {
    Invoke-DisableUAC
    Invoke-GameModeCoreisolation
    Invoke-ShutdownTweaks
    Invoke-MouseTweaks
    Invoke-QuickAccessTweaks
    Invoke-FileDeleteTweaks
    Invoke-LTSCFixes
    Restart-Explorer
}

#region -- WinUtil helper stand-ins

# [ADAPTED] WinUtil's own Write-WinUtilLog writes to its session log file.
# Your script has no WinUtil log, so this prints the same line format to the console.
if (-not (Get-Command Write-WinUtilLog -ErrorAction SilentlyContinue)) {
    function Write-WinUtilLog {
        param(
            [string]$Level = "INFO",
            [string]$Component,
            [string]$Message
        )
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')] [$Level] [$Component] $Message"
    }
}

#endregion


#region -- WinUtil functions (CTT WinUtil Options)

# ---------------------------------------------------------------------------
# WinGet - Reinstall
# Repo (commit 07ccd8e):
#   functions/public/Invoke-WPFFixesWinget.ps1
#   functions/private/Install-WinUtilWinget.ps1
#   functions/private/Test-WinUtilPackageManager.ps1
# ---------------------------------------------------------------------------

function Test-WinUtilPackageManager {

    <#

    .SYNOPSIS
        Checks if WinGet and/or Choco are installed

    .PARAMETER winget
        Check if WinGet is installed

    .PARAMETER choco
        Check if Chocolatey is installed

    #>

    Param(
        [System.Management.Automation.SwitchParameter]$winget,
        [System.Management.Automation.SwitchParameter]$choco
    )

    if ($winget) {
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            $status = "installed"
        } else {
            $status = "not-installed"
        }
    }

    if ($choco) {
        if (Get-Command choco -ErrorAction SilentlyContinue) {
            $status = "installed"
        } else {
            $status = "not-installed"
        }
    }

    return $status
}

function Install-WinUtilWinget {

    <#

    .SYNOPSIS
        Installs WinGet if not already installed.

    .DESCRIPTION
        installs winGet if needed

    #>

    param(
        [switch]$Force
    )

    # The repair action needs Repair-WinGetPackageManager to run even when winget is detected,
    # which is the case a broken installation presents
    if (-not $Force -and (Test-WinUtilPackageManager -winget) -eq "installed") {
        return
    }

    if ($Force) {
        Write-Host "Repairing the WinGet installation..." -ForegroundColor Yellow
    } else {
        Write-Host "WinGet is not installed. Installing now..." -ForegroundColor Red
    }

    Install-PackageProvider -Name NuGet -Force
    Install-Module -Name Microsoft.WinGet.Client -Force
    Repair-WinGetPackageManager -AllUsers
}

function Invoke-WPFFixesWinget {

    <#

    .SYNOPSIS
        Fixes WinGet by running `choco install winget`

    .DESCRIPTION
        BravoNorris for the fantastic idea of a button to reinstall WinGet

    #>

    # [ADAPTED] Repo line here was:  Step-WinUtilJob -Status "Repairing WinGet" -State "Indeterminate"
    # (it drives WinUtil's GUI progress bar, which doesn't exist in your script)
    Write-Host "Repairing WinGet..." -ForegroundColor Cyan

    Install-WinUtilWinget -Force
}


# ---------------------------------------------------------------------------
# Windows Update - Recommended profile
# Repo: functions/public/Invoke-WPFUpdatessecurity.ps1  (main)
# ---------------------------------------------------------------------------
function Invoke-WPFUpdatessecurity {

    <#

    .SYNOPSIS
        Sets Windows Update to recommended settings

    .DESCRIPTION
        1. Disables driver offering through Windows Update
        2. Defers feature updates for 365 days
        3. Defers quality updates for 4 days
        4. Configures automatic updates to notify when downloaded updates are ready to install

    #>

    Write-Host "Disabling driver offering through Windows Update..."
    Write-WinUtilLog -Component "Updates" -Message "Applying recommended Windows Update settings."
    Write-WinUtilLog -Component "Updates" -Message "Disabling driver offering through Windows Update."

    $windowsUpdatePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $automaticUpdatePolicyPath = Join-Path $windowsUpdatePolicyPath "AU"

    Write-Host "Restoring Windows Update availability..."
    Write-WinUtilLog -Component "Updates" -Message "Restoring Windows Update services and scheduled tasks before applying recommended settings."

    Remove-ItemProperty -Path $automaticUpdatePolicyPath -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -ErrorAction SilentlyContinue

    Set-Service -Name BITS -StartupType Manual
    Set-Service -Name wuauserv -StartupType Manual
    Set-Service -Name UsoSvc -StartupType Automatic
    Start-Service -Name UsoSvc

    $Tasks =
        '\Microsoft\Windows\InstallService\*',
        '\Microsoft\Windows\UpdateOrchestrator\*',
        '\Microsoft\Windows\UpdateAssistant\*',
        '\Microsoft\Windows\WaaSMedic\*',
        '\Microsoft\Windows\WindowsUpdate\*',
        '\Microsoft\WindowsUpdate\*'

    foreach ($Task in $Tasks) {
        Get-ScheduledTask -TaskPath $Task -ErrorAction SilentlyContinue | Enable-ScheduledTask -ErrorAction SilentlyContinue
    }

    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1

    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0

    New-Item -Path $windowsUpdatePolicyPath -Force
    Set-ItemProperty -Path $windowsUpdatePolicyPath -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1

    Write-Host "Deferring feature updates by 365 days and quality updates by 4 days..."
    Write-WinUtilLog -Component "Updates" -Message "Deferring feature updates by 365 days and quality updates by 4 days."

    Set-ItemProperty -Path $windowsUpdatePolicyPath -Name "DeferFeatureUpdates" -Type DWord -Value 1
    Set-ItemProperty -Path $windowsUpdatePolicyPath -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 365
    Set-ItemProperty -Path $windowsUpdatePolicyPath -Name "DeferQualityUpdates" -Type DWord -Value 1
    Set-ItemProperty -Path $windowsUpdatePolicyPath -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 4

    $legacySettingsPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
    foreach ($legacyValue in @("BranchReadinessLevel", "DeferFeatureUpdatesPeriodInDays", "DeferQualityUpdatesPeriodInDays")) {
        Remove-ItemProperty -Path $legacySettingsPath -Name $legacyValue -ErrorAction SilentlyContinue
    }

    Write-Host "Configuring automatic updates to download and notify before installation..."
    Write-WinUtilLog -Component "Updates" -Message "Configuring automatic updates to download and notify before installation."

    New-Item -Path $automaticUpdatePolicyPath -Force

    # Remove the previous scheduled-install reboot policy when switching to download-and-notify.
    Remove-ItemProperty -Path $automaticUpdatePolicyPath -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue

    # AUOptions 3 downloads updates and notifies before installation; it does not control restarts.
    Set-ItemProperty -Path $automaticUpdatePolicyPath -Name "AUOptions" -Type DWord -Value 3
    Set-ItemProperty -Path $automaticUpdatePolicyPath -Name "AUPowerManagement" -Type DWord -Value 0

    Write-WinUtilLog -Component "Updates" -Message "Recommended Windows Update settings workflow completed."

}


# ---------------------------------------------------------------------------
# Ultimate Performance Profile - Enable / Disable
# Repo: functions/public/Invoke-WPFUltimatePerformance.ps1
# ---------------------------------------------------------------------------
Function Invoke-WPFUltimatePerformance {
    <#

    .SYNOPSIS
        Enables or disables the Ultimate Performance power scheme based on its GUID.

    .PARAMETER State
        Specifies whether to "Enable" or "Disable" the Ultimate Performance power scheme.

    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Enable", "Disable")]
        [string]$State
    )

    try {
        # GUID of the Ultimate Performance power plan
        $ultimateGUID = "e9a42b02-d5df-448d-aa00-03f14749eb61"

        switch ($State) {
            "Enable" {
                # Duplicate the Ultimate Performance power plan using its GUID
                $duplicateOutput = powercfg /duplicatescheme $ultimateGUID

                $guid = $null
                $nameFromFile = "ChrisTitus - Ultimate Power Plan"
                $description = "Ultimate Power Plan, added via WinUtils"

                # Extract the new GUID from the duplicateOutput
                foreach ($line in $duplicateOutput) {
                    if ($line -match "\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b") {
                        $guid = $matches[0]  # $matches[0] will contain the first match, which is the GUID
                        Write-Output "GUID: $guid has been extracted and stored in the variable."
                        break
                    }
                }

                if (-not $guid) {
                    Write-Output "No GUID found in the duplicateOutput. Check the output format."
                    # [ADAPTED] Repo has "exit 1" here. In your menu script that would close the
                    # whole PowerShell window, so it returns to the menu instead.
                    return
                }

                # Change the name of the power plan and set its description
                $changeNameOutput = powercfg /changename $guid "$nameFromFile" "$description"
                Write-Output "The power plan name and description have been changed. Output:"
                Write-Output $changeNameOutput

                # Set the duplicated Ultimate Performance plan as active
                $setActiveOutput = powercfg /setactive $guid
                Write-Output "The power plan has been set as active. Output:"
                Write-Output $setActiveOutput

                Write-Host "> Ultimate Performance plan installed and set as active."
            }
            "Disable" {
                # Check if the Ultimate Performance plan is installed by GUID
                $installedPlan = powercfg -list | Select-String -Pattern "ChrisTitus - Ultimate Power Plan"

                if ($installedPlan) {
                    # Extract the GUID of the installed Ultimate Performance plan
                    $ultimatePlanGUID = $installedPlan.Line.Split()[3]

                    # Set a different power plan as active before deleting the Ultimate Performance plan
                    $balancedPlanGUID = "381b4222-f694-41f0-9685-ff5bb260df2e"
                    powercfg -setactive $balancedPlanGUID

                    # Delete the Ultimate Performance plan by GUID
                    powercfg -delete $ultimatePlanGUID

                    Write-Host "Ultimate Performance plan has been uninstalled."
                    Write-Host "> Balanced plan is now active."
                } else {
                    Write-Host "Ultimate Performance plan is not installed."
                }
            }
            default {
                Write-Host "Invalid state. Please use 'Enable' or 'Disable'."
            }
        }
    } catch {
        Write-Error "Error occurred: $_"
    }
}

#endregion

function Invoke-CTTWinUtil {
    Write-Host ""
    Write-Host "CTT WinUtil Options:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  1  " -NoNewline -ForegroundColor Cyan; Write-Host "Automated Custom Config  " -NoNewline; Write-Host "(runs 3, 4, 5 below, then your winutil.json)" -ForegroundColor DarkGray
    Write-Host "  2  " -NoNewline -ForegroundColor Cyan; Write-Host "Standard WinUtil"
    Write-Host "  3  " -NoNewline -ForegroundColor Cyan; Write-Host "WinGet - Reinstall"
    Write-Host "  4  " -NoNewline -ForegroundColor Cyan; Write-Host "Windows Update - Recommended Profile"
    Write-Host "  5  " -NoNewline -ForegroundColor Cyan; Write-Host "Ultimate Performance Profile - Enable"
    Write-Host "  6  " -NoNewline -ForegroundColor Cyan; Write-Host "Ultimate Performance Profile - Disable"
    Write-Host "  N  " -NoNewline -ForegroundColor DarkGray; Write-Host "Cancel"
    Write-Host ""

    $command1 = 'iex "& { $(irm https://christitus.com/win) } -Config https://raw.githubusercontent.com/h3kt0rx/powershell/refs/heads/main/cfg/winutil.json -Run"'
    $command2 = "iwr -useb 'https://christitus.com/windev' | iex"

    $choice = Read-Host "Choice"

    switch ($choice) {
        '1' {
            # Step 1/4: WinGet - Reinstall
            Write-Host ""
            Write-Host "[1/4] WinGet - Reinstall" -ForegroundColor Cyan
            try { Invoke-WPFFixesWinget }
            catch { Write-Host "WinGet reinstall failed: $_" -ForegroundColor Red }

            # Step 2/4: Windows Update - Recommended Profile
            Write-Host ""
            Write-Host "[2/4] Windows Update - Recommended Profile" -ForegroundColor Cyan
            try { Invoke-WPFUpdatessecurity }
            catch { Write-Host "Windows Update profile failed: $_" -ForegroundColor Red }

            # Step 3/4: Ultimate Performance Profile - Enable
            Write-Host ""
            Write-Host "[3/4] Ultimate Performance Profile - Enable" -ForegroundColor Cyan
            try { Invoke-WPFUltimatePerformance -State "Enable" }
            catch { Write-Host "Ultimate Performance enable failed: $_" -ForegroundColor Red }

            # Refresh PATH so the new window can see a freshly repaired winget
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

            # Step 4/4: your WinUtil config
            Write-Host ""
            Write-Host "[4/4] Opening new PowerShell window for Automated Custom Config..." -ForegroundColor Green
            Start-Process powershell -ArgumentList "-NoExit", "-Command", $command1
        }
        '2' {
            Write-Host "Opening new PowerShell window for Standard WinUtil..." -ForegroundColor Green
            Start-Process powershell -ArgumentList "-NoExit", "-Command", $command2
        }
        '3' {
            Write-Host "Reinstalling WinGet..." -ForegroundColor Green
            Invoke-WPFFixesWinget
            Write-Host "Done." -ForegroundColor Green
        }
        '4' {
            Write-Host "Applying Windows Update Recommended Profile..." -ForegroundColor Green
            Invoke-WPFUpdatessecurity
            Write-Host "Done." -ForegroundColor Green
        }
        '5' {
            Write-Host "Enabling Ultimate Performance Profile..." -ForegroundColor Green
            Invoke-WPFUltimatePerformance -State "Enable"
        }
        '6' {
            Write-Host "Disabling Ultimate Performance Profile..." -ForegroundColor Green
            Invoke-WPFUltimatePerformance -State "Disable"
        }
        default {
            Write-Host "Cancelled." -ForegroundColor DarkGray
        }
    }
}

function Invoke-LTSCFixes {
    Write-Host ""
    Write-Host "Running Windows LTSC Fixes..." -ForegroundColor Cyan

    # 1. Reset the Microsoft Store (also reinstalls preinstalled apps via -i)
    Write-Host ""
    Write-Host "Resetting Microsoft Store (wsreset -i)..." -ForegroundColor Yellow
    try {
        Start-Process -FilePath "$env:SystemRoot\System32\wsreset.exe" -ArgumentList "-i" -Wait -NoNewWindow -ErrorAction Stop
        Write-Host "Microsoft Store reset complete." -ForegroundColor Green
    } catch {
        Write-Host "wsreset failed: $_" -ForegroundColor Red
    }

    # 2. Install / re-register App Installer (winget)
    Write-Host ""
    Write-Host "Installing App Installer (winget)..." -ForegroundColor Yellow
    try {
        $appInstaller = Get-AppxPackage -Name "Microsoft.DesktopAppInstaller" -ErrorAction SilentlyContinue

        if ($appInstaller) {
            Write-Host "App Installer already present, re-registering..." -ForegroundColor DarkGray
            Add-AppxPackage -RegisterByFamilyName -MainPackage "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe" -ErrorAction Stop
        }
        else {
            $tempDir = "$env:TEMP\AppInstaller"
            New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

            Write-Host "Fetching latest App Installer package..." -ForegroundColor DarkGray
            $release = Invoke-RestMethod -Uri "https://api.github.com/repos/microsoft/winget-cli/releases/latest" -ErrorAction Stop
            $asset   = $release.assets | Where-Object { $_.name -like "*.msixbundle" } | Select-Object -First 1

            if (-not $asset) { throw "Could not locate an .msixbundle asset in the latest winget-cli release." }

            $bundlePath = Join-Path $tempDir $asset.name
            Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $bundlePath -ErrorAction Stop

            Add-AppxPackage -Path $bundlePath -ErrorAction Stop
            Remove-Item -Recurse -Force -Path $tempDir -ErrorAction SilentlyContinue
        }

        Write-Host "App Installer ready." -ForegroundColor Green
    } catch {
        Write-Host "App Installer install failed: $_" -ForegroundColor Red
    }

    # 3. Gaming Services Repair Tool
    Write-Host ""
    Write-Host "Running Gaming Services Repair Tool..." -ForegroundColor Yellow
    try {
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            # Preferred path: winget's package for this tool honors --silent,
            # unlike the standalone GamingRepairTool.exe which has no documented
            # silent switch and will otherwise show its own UI.
            winget install --id Microsoft.Gaming.GamingServicesRepairTool -e `
                            --silent --accept-package-agreements --accept-source-agreements
        }
        else {
            Write-Host "winget not found, falling back to the standalone tool from aka.ms/GamingRepairTool." -ForegroundColor DarkGray
            Write-Host "Note: this build has no documented silent switch, so its own UI may still appear." -ForegroundColor DarkGray

            $toolPath = "$env:TEMP\GamingRepairTool.exe"
            Invoke-WebRequest -Uri "https://aka.ms/GamingRepairTool" -OutFile $toolPath -ErrorAction Stop
            Start-Process -FilePath $toolPath -Wait -ErrorAction Stop
        }

        Write-Host "Gaming Services Repair Tool finished." -ForegroundColor Green
    } catch {
        Write-Host "Gaming Services Repair Tool failed: $_" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "LTSC Fixes complete." -ForegroundColor Green
}

#endregion

#region ── Main Loop ────────────────────────────────────────────────────────────

do {
    Show-Menu
    $selection = Read-Host "Enter option"
    $command1 = 'iex "& { $(irm https://christitus.com/win) } -Config https://raw.githubusercontent.com/h3kt0rx/powershell/refs/heads/main/cfg/winutil.json -Run"'

    switch ($selection.ToUpper()) {
        '1' {
            Write-Host ""
            Write-Host "[1/7] Windows 11/LTSC Tweaks and Fixes" -ForegroundColor Cyan
            try { Invoke-WindowsTweaks }
            catch { Write-Host "Windows 11/LTSC Tweaks and Fixes failed: $_" -ForegroundColor Red }

            Write-Host ""
            Write-Host "[2/7] NVIDIA Profile Setup" -ForegroundColor Cyan
            try { Invoke-NvidiaProfile }
            catch { Write-Host "NVIDIA Profile Setup failed: $_" -ForegroundColor Red }

            Write-Host ""
            Write-Host "[3/7] O&O ShutUp 10" -ForegroundColor Cyan
            try { Invoke-OOShutUp }
            catch { Write-Host "O&O ShutUp 10 failed: $_" -ForegroundColor Red }

            Write-Host ""
            Write-Host "[4/7] WinGet - Reinstall" -ForegroundColor Cyan
            try { Invoke-WPFFixesWinget }
            catch { Write-Host "WinGet reinstall failed: $_" -ForegroundColor Red }

            # Step 2/4: Windows Update - Recommended Profile
            Write-Host ""
            Write-Host "[5/7] Windows Update - Recommended Profile" -ForegroundColor Cyan
            try { Invoke-WPFUpdatessecurity }
            catch { Write-Host "Windows Update profile failed: $_" -ForegroundColor Red }

            # Step 3/4: Ultimate Performance Profile - Enable
            Write-Host ""
            Write-Host "[6/7] Ultimate Performance Profile - Enable" -ForegroundColor Cyan
            try { Invoke-WPFUltimatePerformance -State "Enable" }
            catch { Write-Host "Ultimate Performance enable failed: $_" -ForegroundColor Red }

            # Refresh PATH so the new window can see a freshly repaired winget
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

            # Step 4/4: your WinUtil config
            Write-Host ""
            Write-Host "[7/7] Opening new PowerShell window for Automated Custom Config..." -ForegroundColor Green
            Start-Process powershell -ArgumentList "-NoExit", "-Command", $command1
            Pause-Menu
        }
        '2' {
            Invoke-WindowsTweaks
            Pause-Menu
        }
        '3' {
            Invoke-NvidiaProfile
            Pause-Menu
        }
        '4' {
            Invoke-OOShutUp
            Pause-Menu
        }
        '5' {
            Invoke-CTTWinUtil
            Pause-Menu
        }
        '6' {
            Write-Host "Launching Microsoft Activation Scripts (MAS)" -ForegroundColor Cyan
            irm https://get.activated.win | iex
            Write-Host "Done." -ForegroundColor Green
            Pause-Menu
        }
        'X' {
            Write-Host "`nExiting. Goodbye!`n" -ForegroundColor DarkCyan
        }
        default {
            Write-Host "`nInvalid option. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} while ($selection.ToUpper() -ne 'X')

#endregion