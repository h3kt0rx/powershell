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
Write-Host "Setting NVIDIA Profile" -ForegroundColor Cyan
# Define URLs
$zipUrl = "https://github.com/h3kt0rx/powershell/raw/refs/heads/main/cfg/nvidiaProfileInspector.zip"
$configUrl = "https://github.com/h3kt0rx/powershell/raw/refs/heads/main/cfg/custom.nip"
# Define temporary paths
$tempDir = "$env:TEMP\nvidiaProfileInspector"
$zipPath = "$tempDir\nvidiaProfileInspector.zip"
$extractPath = "$tempDir\nvidiaProfileInspector"
# Create the directory and suppress output
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
# Download the ZIP file and suppress output
Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath | Out-Null
# Extract the ZIP file and suppress output
Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force | Out-Null
# Download the configuration file and suppress output
Invoke-WebRequest -Uri $configUrl -OutFile "$extractPath\custom.nip" | Out-Null
# Run the command to import the profile silently
$process = Start-Process -FilePath $extractPath\nvidiaProfileInspector.exe -ArgumentList "-silentImport `"$extractPath\custom.nip`"" -PassThru
# Wait for the process to exit
$process.WaitForExit()
# Clean up
Remove-Item -Recurse -Force -Path $tempDir
Write-Host "Done." -ForegroundColor Green
############################################################################################################################################################
<# Script to Disable Core Isolation and Enable Game Mode #>
############################################################################################################################################################
Write-Host "Enabling Game Mode and Disabling Core Isolation" -ForegroundColor Cyan

# Enable Game Mode using reg add
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v UseGameMode /t REG_DWORD /d 1 /f

# Disable Core Isolation Memory Integrity using reg add
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f

Write-Host "Done." -ForegroundColor Green
############################################################################################################################################################
<# Run O&O ShutUp #>
############################################################################################################################################################
Write-Host "Running O&O ShutUp" -ForegroundColor Cyan
$OOSU_filepath = "$ENV:temp\OOSU10.exe"
$oosu_config = "$ENV:temp\ooshutup10.cfg"
Invoke-WebRequest -Uri "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -OutFile $OOSU_filepath
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/h3kt0rx/powershell/refs/heads/main/cfg/ooshutup10.cfg" -OutFile $oosu_config
Write-Host "Applying personal O&O Shutup 10 Policies"
Start-Process $OOSU_filepath -ArgumentList "$oosu_config /quiet" -Wait
Write-Host "Done." -ForegroundColor Green
############################################################################################################################################################
<# Remove Gamebar #>
############################################################################################################################################################
Write-Host "Removing Gamebar"  -ForegroundColor Cyan
# disable gamebar regedit
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f | Out-Null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f | Out-Null
# disable open xbox game bar using game controller regedit
reg add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f | Out-Null
# disable gameinput service regedit
reg add "HKLM\SYSTEM\ControlSet001\Services\GameInputSvc" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
# disable gamedvr and broadcast user service regedit
reg add "HKLM\SYSTEM\ControlSet001\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
# disable xbox accessory management service regedit
reg add "HKLM\SYSTEM\ControlSet001\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
# disable xbox live auth manager service regedit
reg add "HKLM\SYSTEM\ControlSet001\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
# disable xbox live game save service regedit
reg add "HKLM\SYSTEM\ControlSet001\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
# disable xbox live networking service regedit
reg add "HKLM\SYSTEM\ControlSet001\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
Write-Host "Done." -ForegroundColor Green
# disable ms-gamebar notifications with xbox controller plugged in regedit
Write-Host "Disabling Game Bar Notifications Triggered by Xbox Controller" -ForegroundColor Cyan
# ms-gamebar
reg delete "HKCR\ms-gamebar" /f
reg add "HKCR\ms-gamebar" /ve /d "URL:ms-gamebar" /f
reg add "HKCR\ms-gamebar" /v "URL Protocol" /t REG_SZ /d "" /f
reg add "HKCR\ms-gamebar" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKCR\ms-gamebar\shell\open\command" /ve /d '\"%SystemRoot%\\System32\\systray.exe\"' /f
# ms-gamebarservices
reg delete "HKCR\ms-gamebarservices" /f
reg add "HKCR\ms-gamebarservices" /ve /d "URL:ms-gamebarservices" /f
reg add "HKCR\ms-gamebarservices" /v "URL Protocol" /t REG_SZ /d "" /f
reg add "HKCR\ms-gamebarservices" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKCR\ms-gamebarservices\shell\open\command" /ve /d '\"%SystemRoot%\\System32\\systray.exe\"' /f
# ms-gamingoverlay
reg delete "HKCR\ms-gamingoverlay" /f
reg add "HKCR\ms-gamingoverlay" /ve /d "URL:ms-gamingoverlay" /f
reg add "HKCR\ms-gamingoverlay" /v "URL Protocol" /t REG_SZ /d "" /f
reg add "HKCR\ms-gamingoverlay" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKCR\ms-gamingoverlay\shell\open\command" /ve /d '\"%SystemRoot%\System32\systray.exe\"' /f
# stop gamebar running
Stop-Process -Force -Name GameBar -ErrorAction SilentlyContinue | Out-Null
# uninstall gamebar & xbox apps
Get-AppxPackage -allusers *Microsoft.GamingApp* | Remove-AppxPackage
Get-AppxPackage -allusers *Microsoft.Xbox.TCUI* | Remove-AppxPackage
Get-AppxPackage -allusers *Microsoft.XboxApp* | Remove-AppxPackage
Get-AppxPackage -allusers *Microsoft.XboxGameOverlay* | Remove-AppxPackage
Get-AppxPackage -allusers *Microsoft.XboxGamingOverlay* | Remove-AppxPackage
Get-AppxPackage -allusers *Microsoft.XboxIdentityProvider* | Remove-AppxPackage
Get-AppxPackage -allusers *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage
Write-Host "Done." -ForegroundColor Green

############################################################################################################################################################
<# Registry #>
############################################################################################################################################################
Write-Host "Running Registry Tweaks" -ForegroundColor Cyan

#--------------------------------
# APPEARANCE AND PERSONALIZATION
#--------------------------------

# Hide frequent folders in Quick Access
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d 0 /f
# Show file-name extensions
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
# Disable search history
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDeviceSearchHistoryEnabled" /t REG_DWORD /d 0 /f

#--------
# GAMING
#--------

# Disable the Game Bar to prevent its use
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f
# Disable app capture feature in Game DVR
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f


#---------------------------
# FASTER SHUTDOWN TWEAKS
#---------------------------

# Force hung apps to close faster
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
# Set hung app timeout
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
# Set wait-to-kill time for user apps
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "1000" /f
# Set wait-to-kill time for services
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f


#-------
# MOUSE
#-------

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
<# C++ Installation #>
############################################################################################################################################################
$install = Read-Host "Do you want to install C++ Redistributable dependencies for games? (Y/N)"
if ($install -match "[Yy]") {
    Write-Host "Installing C++ for running applications" -ForegroundColor Cyan

    function Get-FileFromWeb {
        param (
            [Parameter(Mandatory)][string]$URL, 
            [Parameter(Mandatory)][string]$File
        )
        function Show-Progress {
            param (
                [Parameter(Mandatory)][Single]$TotalValue, 
                [Parameter(Mandatory)][Single]$CurrentValue, 
                [Parameter(Mandatory)][string]$ProgressText, 
                [Parameter()][int]$BarSize = 10, 
                [Parameter()][switch]$Complete
            )
            $percent = $CurrentValue / $TotalValue
            $percentComplete = $percent * 100
            if ($psISE) { 
                Write-Progress "$ProgressText" -id 0 -percentComplete $percentComplete 
            } else { 
                Write-Host -NoNewLine "`r$ProgressText $(''.PadRight($BarSize * $percent, [char]9608).PadRight($BarSize, [char]9617)) $($percentComplete.ToString('##0.00').PadLeft(6)) % " 
            }
        }
        try {
            $request = [System.Net.HttpWebRequest]::Create($URL)
            $response = $request.GetResponse()
            if ($response.StatusCode -eq 401 -or $response.StatusCode -eq 403 -or $response.StatusCode -eq 404) { 
                throw "Remote file either doesn't exist, is unauthorized, or is forbidden for '$URL'." 
            }
            if ($File -match '^\.\\') { 
                $File = Join-Path (Get-Location -PSProvider 'FileSystem') ($File -Split '^\.')[1] 
            }
            if ($File -and !(Split-Path $File)) { 
                $File = Join-Path (Get-Location -PSProvider 'FileSystem') $File 
            }
            if ($File) { 
                $fileDirectory = $([System.IO.Path]::GetDirectoryName($File)); 
                if (!(Test-Path($fileDirectory))) { 
                    [System.IO.Directory]::CreateDirectory($fileDirectory) | Out-Null 
                } 
            }
            [long]$fullSize = $response.ContentLength
            [byte[]]$buffer = new-object byte[] 1048576
            [long]$total = [long]$count = 0
            $reader = $response.GetResponseStream()
            $writer = new-object System.IO.FileStream $File, 'Create'
            do {
                $count = $reader.Read($buffer, 0, $buffer.Length)
                $writer.Write($buffer, 0, $count)
                $total += $count
                if ($fullSize -gt 0) { Show-Progress -TotalValue $fullSize -CurrentValue $total -ProgressText " $($File.Name)" }
            } while ($count -gt 0)
        }
        finally {
            $reader.Close()
            $writer.Close()
        }
    }

    # Download and install C++ Redistributables
    $files = @{
        "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE" = "$env:TEMP\vcredist2005_x86.exe"
        "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x64.EXE" = "$env:TEMP\vcredist2005_x64.exe"
        "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe" = "$env:TEMP\vcredist2008_x86.exe"
        "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x64.exe" = "$env:TEMP\vcredist2008_x64.exe"
        "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x86.exe" = "$env:TEMP\vcredist2010_x86.exe"
        "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe" = "$env:TEMP\vcredist2010_x64.exe"
        "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe" = "$env:TEMP\vcredist2012_x86.exe"
        "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe" = "$env:TEMP\vcredist2012_x64.exe"
        "https://aka.ms/highdpimfc2013x86enu" = "$env:TEMP\vcredist2013_x86.exe"
        "https://aka.ms/highdpimfc2013x64enu" = "$env:TEMP\vcredist2013_x64.exe"
        "https://aka.ms/vs/17/release/vc_redist.x86.exe" = "$env:TEMP\vcredist2015_2017_2019_2022_x86.exe"
        "https://aka.ms/vs/17/release/vc_redist.x64.exe" = "$env:TEMP\vcredist2015_2017_2019_2022_x64.exe"
    }

    foreach ($url in $files.Keys) {
        Get-FileFromWeb -URL $url -File $files[$url]
    }

    # Start installers
    $arguments = @("/q", "/qb", "/passive /norestart")
    $files.Values | ForEach-Object {
        $argIndex = 0
        if ($_ -match "2008") { $argIndex = 1 }
        elseif ($_ -match "2010|2012|2013|2015|2017|2019|2022") { $argIndex = 2 }
        Start-Process -wait $_ -ArgumentList $arguments[$argIndex]
    }

    Write-Host "Done." -ForegroundColor Green
} else {
    Write-Host "Installation Skipped." -ForegroundColor Cyan
}

############################################################################################################################################################
<# Direct X Installation #>
############################################################################################################################################################

# Ask the user if they want to install DirectX
$installDirectX = Read-Host "Do you want to install DirectX? (Y/N)"

if ($installDirectX -match '^[Yy]$') {
    Write-Host "Installing DirectX..." -ForegroundColor Cyan

    # Define the URL and paths
    $DXFileUri = "https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe"
    $DXFileUri2 = "https://www.7-zip.org/a/7z2301-x64.exe"
    $DXDestination = "$env:TEMP\directx_Jun2010_redist.exe"
    $DXDestination2 = "$env:TEMP\7-Zip.exe"
    $DXExtractPath = "$env:TEMP\DirectX_Install"

    # Download DirectX installer
    Write-Host "Downloading DirectX..." -ForegroundColor Yellow
    $DXbitsJobObj = Start-BitsTransfer -Source $DXFileUri -Destination $DXDestination
    $DXbitsJobObj = Start-BitsTransfer -Source $DXFileUri2 -Destination $DXDestination2

    switch ($DXbitsJobObj.JobState) {
        'Transferred' {
            Complete-BitsTransfer -BitsJob $DXbitsJobObj
            break
        }
        'Error' {
            throw 'Error downloading'
        }
    }

    # Create the extraction directory if it doesn't exist
    if (-Not (Test-Path -Path $DXExtractPath)) {
        New-Item -ItemType Directory -Path $DXExtractPath | Out-Null
    }

    # Install 7-Zip silently
    Write-Host "Installing 7-Zip..." -ForegroundColor Yellow
    Start-Process -Wait "$env:TEMP\7-Zip.exe" /S

    # Extract DirectX installer using 7-Zip
    Write-Host "Extracting DirectX installer..." -ForegroundColor Yellow
    cmd /c '"C:\Program Files\7-Zip\7z.exe" x "'$DXDestination'" -o"'$DXExtractPath'" -y' | Out-Null

    # Install DirectX silently
    Write-Host "Running DirectX setup..." -ForegroundColor Yellow
    Start-Process "$DXExtractPath\DXSETUP.exe" -ArgumentList "/silent" -Wait

    # Clean up
    Write-Host "Cleaning up..." -ForegroundColor Yellow
    Remove-Item -Path $DXDestination -Force

    Write-Host "DirectX installation complete." -ForegroundColor Green
} else {
    Write-Host "DirectX installation skipped." -ForegroundColor Cyan
}
############################################################################################################################################################
<# Run Titus Script #>
############################################################################################################################################################
# PowerShell script to prompt before running commands
$command1 = 'iex \"& { $(irm https://christitus.com/win) } -Config https://raw.githubusercontent.com/h3kt0rx/powershell/refs/heads/main/cfg/winutil.json -Run\"'
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
#iex "& { $(irm https://christitus.com/windev) } -Config https://raw.githubusercontent.com/h3kt0rx/powershell/refs/heads/main/cfg/winutil.json -Run"
############################################################################################################################################################
# Personal Programs
############################################################################################################################################################
# Prompt the user
# $installPersonalApps = Read-Host "Do you want to install personal applications before running? (Y/N)"

# If the user responds with Y or y, proceed with the installation of personal applications
# if ($installPersonalApps -eq 'Y' -or $installPersonalApps -eq 'y') {
#     Write-Output "Installing Chocolatey"
#     choco install chocolatey-core.extension -y

#     Write-Output "Installing Personal Applications"
#     choco install discord.install -y
#     choco install notepadplusplus.install -y
#     choco install peazip.install -y
#     choco install vlc.install -y
#     choco install steam -y
#     choco install ddu -y
#     choco install tightvnc -y
#     choco install rustdesk -y
# } else {
#     Write-Output "Skipping Personal Applications installation."
# }

#Write-Output "Running Spotify Install Script"
#iex "& { $(iwr -useb 'https://raw.githubusercontent.com/SpotX-Official/spotx-official.github.io/main/run.ps1') } -new_theme"


#dolby atmos
#Peace GUI
#fiio
#autodesk fusion
#davinci resolve
 ############################################################################################################################################################
<# Timer Resolution #>
############################################################################################################################################################
Write-Host "Installing: Set Timer Resolution Service" -ForegroundColor Cyan
# create .cs file
$MultilineComment = @"
using System;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.ComponentModel;
using System.Configuration.Install;
using System.Collections.Generic;
using System.Reflection;
using System.IO;
using System.Management;
using System.Threading;
using System.Diagnostics;
[assembly: AssemblyVersion("2.1")]
[assembly: AssemblyProduct("Set Timer Resolution service")]
namespace WindowsService
{
    class WindowsService : ServiceBase
    {
        public WindowsService()
        {
            this.ServiceName = "STR";
            this.EventLog.Log = "Application";
            this.CanStop = true;
            this.CanHandlePowerEvent = false;
            this.CanHandleSessionChangeEvent = false;
            this.CanPauseAndContinue = false;
            this.CanShutdown = false;
        }
        static void Main()
        {
            ServiceBase.Run(new WindowsService());
        }
        protected override void OnStart(string[] args)
        {
            base.OnStart(args);
            ReadProcessList();
            NtQueryTimerResolution(out this.MininumResolution, out this.MaximumResolution, out this.DefaultResolution);
            if(null != this.EventLog)
                try { this.EventLog.WriteEntry(String.Format("Minimum={0}; Maximum={1}; Default={2}; Processes='{3}'", this.MininumResolution, this.MaximumResolution, this.DefaultResolution, null != this.ProcessesNames ? String.Join("','", this.ProcessesNames) : "")); }
                catch {}
            if(null == this.ProcessesNames)
            {
                SetMaximumResolution();
                return;
            }
            if(0 == this.ProcessesNames.Count)
            {
                return;
            }
            this.ProcessStartDelegate = new OnProcessStart(this.ProcessStarted);
            try
            {
                String query = String.Format("SELECT * FROM __InstanceCreationEvent WITHIN 0.5 WHERE (TargetInstance isa \"Win32_Process\") AND (TargetInstance.Name=\"{0}\")", String.Join("\" OR TargetInstance.Name=\"", this.ProcessesNames));
                this.startWatch = new ManagementEventWatcher(query);
                this.startWatch.EventArrived += this.startWatch_EventArrived;
                this.startWatch.Start();
            }
            catch(Exception ee)
            {
                if(null != this.EventLog)
                    try { this.EventLog.WriteEntry(ee.ToString(), EventLogEntryType.Error); }
                    catch {}
            }
        }
        protected override void OnStop()
        {
            if(null != this.startWatch)
            {
                this.startWatch.Stop();
            }

            base.OnStop();
        }
        ManagementEventWatcher startWatch;
        void startWatch_EventArrived(object sender, EventArrivedEventArgs e) 
        {
            try
            {
                ManagementBaseObject process = (ManagementBaseObject)e.NewEvent.Properties["TargetInstance"].Value;
                UInt32 processId = (UInt32)process.Properties["ProcessId"].Value;
                this.ProcessStartDelegate.BeginInvoke(processId, null, null);
            } 
            catch(Exception ee) 
            {
                if(null != this.EventLog)
                    try { this.EventLog.WriteEntry(ee.ToString(), EventLogEntryType.Warning); }
                    catch {}

            }
        }
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern Int32 WaitForSingleObject(IntPtr Handle, Int32 Milliseconds);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern IntPtr OpenProcess(UInt32 DesiredAccess, Int32 InheritHandle, UInt32 ProcessId);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern Int32 CloseHandle(IntPtr Handle);
        const UInt32 SYNCHRONIZE = 0x00100000;
        delegate void OnProcessStart(UInt32 processId);
        OnProcessStart ProcessStartDelegate = null;
        void ProcessStarted(UInt32 processId)
        {
            SetMaximumResolution();
            IntPtr processHandle = IntPtr.Zero;
            try
            {
                processHandle = OpenProcess(SYNCHRONIZE, 0, processId);
                if(processHandle != IntPtr.Zero)
                    WaitForSingleObject(processHandle, -1);
            } 
            catch(Exception ee) 
            {
                if(null != this.EventLog)
                    try { this.EventLog.WriteEntry(ee.ToString(), EventLogEntryType.Warning); }
                    catch {}
            }
            finally
            {
                if(processHandle != IntPtr.Zero)
                    CloseHandle(processHandle); 
            }
            SetDefaultResolution();
        }
        List<String> ProcessesNames = null;
        void ReadProcessList()
        {
            String iniFilePath = Assembly.GetExecutingAssembly().Location + ".ini";
            if(File.Exists(iniFilePath))
            {
                this.ProcessesNames = new List<String>();
                String[] iniFileLines = File.ReadAllLines(iniFilePath);
                foreach(var line in iniFileLines)
                {
                    String[] names = line.Split(new char[] {',', ' ', ';'} , StringSplitOptions.RemoveEmptyEntries);
                    foreach(var name in names)
                    {
                        String lwr_name = name.ToLower();
                        if(!lwr_name.EndsWith(".exe"))
                            lwr_name += ".exe";
                        if(!this.ProcessesNames.Contains(lwr_name))
                            this.ProcessesNames.Add(lwr_name);
                    }
                }
            }
        }
        [DllImport("ntdll.dll", SetLastError=true)]
        static extern int NtSetTimerResolution(uint DesiredResolution, bool SetResolution, out uint CurrentResolution);
        [DllImport("ntdll.dll", SetLastError=true)]
        static extern int NtQueryTimerResolution(out uint MinimumResolution, out uint MaximumResolution, out uint ActualResolution);
        uint DefaultResolution = 0;
        uint MininumResolution = 0;
        uint MaximumResolution = 0;
        long processCounter = 0;
        void SetMaximumResolution()
        {
            long counter = Interlocked.Increment(ref this.processCounter);
            if(counter <= 1)
            {
                uint actual = 0;
                NtSetTimerResolution(this.MaximumResolution, true, out actual);
                if(null != this.EventLog)
                    try { this.EventLog.WriteEntry(String.Format("Actual resolution = {0}", actual)); }
                    catch {}
            }
        }
        void SetDefaultResolution()
        {
            long counter = Interlocked.Decrement(ref this.processCounter);
            if(counter < 1)
            {
                uint actual = 0;
                NtSetTimerResolution(this.DefaultResolution, true, out actual);
                if(null != this.EventLog)
                    try { this.EventLog.WriteEntry(String.Format("Actual resolution = {0}", actual)); }
                    catch {}
            }
        }
    }
    [RunInstaller(true)]
    public class WindowsServiceInstaller : Installer
    {
        public WindowsServiceInstaller()
        {
            ServiceProcessInstaller serviceProcessInstaller = 
                               new ServiceProcessInstaller();
            ServiceInstaller serviceInstaller = new ServiceInstaller();
            serviceProcessInstaller.Account = ServiceAccount.LocalSystem;
            serviceProcessInstaller.Username = null;
            serviceProcessInstaller.Password = null;
            serviceInstaller.DisplayName = "Set Timer Resolution Service";
            serviceInstaller.StartType = ServiceStartMode.Automatic;
            serviceInstaller.ServiceName = "STR";
            this.Installers.Add(serviceProcessInstaller);
            this.Installers.Add(serviceInstaller);
        }
    }
}
"@
Set-Content -Path "$env:C:\Windows\SetTimerResolutionService.cs" -Value $MultilineComment -Force
# compile and create service
Start-Process -Wait "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" -ArgumentList "-out:C:\Windows\SetTimerResolutionService.exe C:\Windows\SetTimerResolutionService.cs" -WindowStyle Hidden
# delete file
Remove-Item "$env:C:\Windows\SetTimerResolutionService.cs" -ErrorAction SilentlyContinue | Out-Null
# install and start service
New-Service -Name "Set Timer Resolution Service" -BinaryPathName "$env:C:\Windows\SetTimerResolutionService.exe" -ErrorAction SilentlyContinue | Out-Null
Set-Service -Name "Set Timer Resolution Service" -StartupType Automatic -ErrorAction SilentlyContinue | Out-Null
Set-Service -Name "Set Timer Resolution Service" -Status Running -ErrorAction SilentlyContinue | Out-Null
# fix timer resolution regedit
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "GlobalTimerResolutionRequests" /t REG_DWORD /d "1" /f | Out-Null
Write-Host "Done."  -ForegroundColor Green
Write-Host "Restart your computer for settings to take effect." -ForegroundColor Red
pause