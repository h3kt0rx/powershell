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

        # # turn on no scaling for all displays
        # $configKeys = Get-ChildItem -Path "HKLM:\System\ControlSet001\Control\GraphicsDrivers\Configuration" -Recurse -ErrorAction SilentlyContinue
        # foreach ($key in $configKeys) {
        # $scalingValue = Get-ItemProperty -Path $key.PSPath -Name "Scaling" -ErrorAction SilentlyContinue
        # if ($scalingValue) {
        # $regPath = $key.PSPath.Replace('Microsoft.PowerShell.Core\Registry::', '').Replace('HKEY_LOCAL_MACHINE', 'HKLM')
        # Run-Trusted -command "reg add `"$regPath`" /v `"Scaling`" /t REG_DWORD /d `"2`" /f"
        # }
        foreach ($display in $displays) {
            $regPath = $display.PSPath -replace 'Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE', 'HKLM:'

            Set-ItemProperty -Path $regPath `
                -Name "ScalingConfig" `
                -Value ([byte[]](0xDB,0x02,0x00,0x00,0x10,0x00,0x00,0x00,0x20,0x01,0x00,0x00,0x0E,0x01,0x00,0x00)) `
                -Type Binary
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
# ############################################################################################################################################################
# <# Script to Disable Core Isolation and Enable Game Mode #>
# ############################################################################################################################################################
# Write-Host "Enabling Game Mode and Disabling Core Isolation" -ForegroundColor Cyan

# # Enable Game Mode using reg add
# reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 1 /f
# reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v UseGameMode /t REG_DWORD /d 1 /f

# # Disable Core Isolation Memory Integrity using reg add
# reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f

# Write-Host "Done." -ForegroundColor Green
# ############################################################################################################################################################
# <# Run O&O ShutUp #>
# ############################################################################################################################################################
# Write-Host "Running O&O ShutUp" -ForegroundColor Cyan
# $OOSU_filepath = "$ENV:temp\OOSU10.exe"
# $oosu_config = "$ENV:temp\ooshutup10.cfg"
# Invoke-WebRequest -Uri "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -OutFile $OOSU_filepath
# Invoke-WebRequest -Uri "https://raw.githubusercontent.com/h3kt0rx/powershell/refs/heads/main/cfg/ooshutup10.cfg" -OutFile $oosu_config
# Write-Host "Applying personal O&O Shutup 10 Policies"
# Start-Process $OOSU_filepath -ArgumentList "$oosu_config /quiet" -Wait
# Write-Host "Done." -ForegroundColor Green

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


#Write-Output "Running Spotify Install Script"
#iex "& { $(iwr -useb 'https://raw.githubusercontent.com/SpotX-Official/spotx-official.github.io/main/run.ps1') } -new_theme"


############################################################################################################################################################
<# Timer Resolution #>
############################################################################################################################################################
# Write-Host "Installing: Set Timer Resolution Service" -ForegroundColor Cyan
# # create .cs file
# $MultilineComment = @"
# using System;
# using System.Runtime.InteropServices;
# using System.ServiceProcess;
# using System.ComponentModel;
# using System.Configuration.Install;
# using System.Collections.Generic;
# using System.Reflection;
# using System.IO;
# using System.Management;
# using System.Threading;
# using System.Diagnostics;
# [assembly: AssemblyVersion("2.1")]
# [assembly: AssemblyProduct("Set Timer Resolution service")]
# namespace WindowsService
# {
#     class WindowsService : ServiceBase
#     {
#         public WindowsService()
#         {
#             this.ServiceName = "STR";
#             this.EventLog.Log = "Application";
#             this.CanStop = true;
#             this.CanHandlePowerEvent = false;
#             this.CanHandleSessionChangeEvent = false;
#             this.CanPauseAndContinue = false;
#             this.CanShutdown = false;
#         }
#         static void Main()
#         {
#             ServiceBase.Run(new WindowsService());
#         }
#         protected override void OnStart(string[] args)
#         {
#             base.OnStart(args);
#             ReadProcessList();
#             NtQueryTimerResolution(out this.MininumResolution, out this.MaximumResolution, out this.DefaultResolution);
#             if(null != this.EventLog)
#                 try { this.EventLog.WriteEntry(String.Format("Minimum={0}; Maximum={1}; Default={2}; Processes='{3}'", this.MininumResolution, this.MaximumResolution, this.DefaultResolution, null != this.ProcessesNames ? String.Join("','", this.ProcessesNames) : "")); }
#                 catch {}
#             if(null == this.ProcessesNames)
#             {
#                 SetMaximumResolution();
#                 return;
#             }
#             if(0 == this.ProcessesNames.Count)
#             {
#                 return;
#             }
#             this.ProcessStartDelegate = new OnProcessStart(this.ProcessStarted);
#             try
#             {
#                 String query = String.Format("SELECT * FROM __InstanceCreationEvent WITHIN 0.5 WHERE (TargetInstance isa \"Win32_Process\") AND (TargetInstance.Name=\"{0}\")", String.Join("\" OR TargetInstance.Name=\"", this.ProcessesNames));
#                 this.startWatch = new ManagementEventWatcher(query);
#                 this.startWatch.EventArrived += this.startWatch_EventArrived;
#                 this.startWatch.Start();
#             }
#             catch(Exception ee)
#             {
#                 if(null != this.EventLog)
#                     try { this.EventLog.WriteEntry(ee.ToString(), EventLogEntryType.Error); }
#                     catch {}
#             }
#         }
#         protected override void OnStop()
#         {
#             if(null != this.startWatch)
#             {
#                 this.startWatch.Stop();
#             }

#             base.OnStop();
#         }
#         ManagementEventWatcher startWatch;
#         void startWatch_EventArrived(object sender, EventArrivedEventArgs e) 
#         {
#             try
#             {
#                 ManagementBaseObject process = (ManagementBaseObject)e.NewEvent.Properties["TargetInstance"].Value;
#                 UInt32 processId = (UInt32)process.Properties["ProcessId"].Value;
#                 this.ProcessStartDelegate.BeginInvoke(processId, null, null);
#             } 
#             catch(Exception ee) 
#             {
#                 if(null != this.EventLog)
#                     try { this.EventLog.WriteEntry(ee.ToString(), EventLogEntryType.Warning); }
#                     catch {}

#             }
#         }
#         [DllImport("kernel32.dll", SetLastError=true)]
#         static extern Int32 WaitForSingleObject(IntPtr Handle, Int32 Milliseconds);
#         [DllImport("kernel32.dll", SetLastError=true)]
#         static extern IntPtr OpenProcess(UInt32 DesiredAccess, Int32 InheritHandle, UInt32 ProcessId);
#         [DllImport("kernel32.dll", SetLastError=true)]
#         static extern Int32 CloseHandle(IntPtr Handle);
#         const UInt32 SYNCHRONIZE = 0x00100000;
#         delegate void OnProcessStart(UInt32 processId);
#         OnProcessStart ProcessStartDelegate = null;
#         void ProcessStarted(UInt32 processId)
#         {
#             SetMaximumResolution();
#             IntPtr processHandle = IntPtr.Zero;
#             try
#             {
#                 processHandle = OpenProcess(SYNCHRONIZE, 0, processId);
#                 if(processHandle != IntPtr.Zero)
#                     WaitForSingleObject(processHandle, -1);
#             } 
#             catch(Exception ee) 
#             {
#                 if(null != this.EventLog)
#                     try { this.EventLog.WriteEntry(ee.ToString(), EventLogEntryType.Warning); }
#                     catch {}
#             }
#             finally
#             {
#                 if(processHandle != IntPtr.Zero)
#                     CloseHandle(processHandle); 
#             }
#             SetDefaultResolution();
#         }
#         List<String> ProcessesNames = null;
#         void ReadProcessList()
#         {
#             String iniFilePath = Assembly.GetExecutingAssembly().Location + ".ini";
#             if(File.Exists(iniFilePath))
#             {
#                 this.ProcessesNames = new List<String>();
#                 String[] iniFileLines = File.ReadAllLines(iniFilePath);
#                 foreach(var line in iniFileLines)
#                 {
#                     String[] names = line.Split(new char[] {',', ' ', ';'} , StringSplitOptions.RemoveEmptyEntries);
#                     foreach(var name in names)
#                     {
#                         String lwr_name = name.ToLower();
#                         if(!lwr_name.EndsWith(".exe"))
#                             lwr_name += ".exe";
#                         if(!this.ProcessesNames.Contains(lwr_name))
#                             this.ProcessesNames.Add(lwr_name);
#                     }
#                 }
#             }
#         }
#         [DllImport("ntdll.dll", SetLastError=true)]
#         static extern int NtSetTimerResolution(uint DesiredResolution, bool SetResolution, out uint CurrentResolution);
#         [DllImport("ntdll.dll", SetLastError=true)]
#         static extern int NtQueryTimerResolution(out uint MinimumResolution, out uint MaximumResolution, out uint ActualResolution);
#         uint DefaultResolution = 0;
#         uint MininumResolution = 0;
#         uint MaximumResolution = 0;
#         long processCounter = 0;
#         void SetMaximumResolution()
#         {
#             long counter = Interlocked.Increment(ref this.processCounter);
#             if(counter <= 1)
#             {
#                 uint actual = 0;
#                 NtSetTimerResolution(this.MaximumResolution, true, out actual);
#                 if(null != this.EventLog)
#                     try { this.EventLog.WriteEntry(String.Format("Actual resolution = {0}", actual)); }
#                     catch {}
#             }
#         }
#         void SetDefaultResolution()
#         {
#             long counter = Interlocked.Decrement(ref this.processCounter);
#             if(counter < 1)
#             {
#                 uint actual = 0;
#                 NtSetTimerResolution(this.DefaultResolution, true, out actual);
#                 if(null != this.EventLog)
#                     try { this.EventLog.WriteEntry(String.Format("Actual resolution = {0}", actual)); }
#                     catch {}
#             }
#         }
#     }
#     [RunInstaller(true)]
#     public class WindowsServiceInstaller : Installer
#     {
#         public WindowsServiceInstaller()
#         {
#             ServiceProcessInstaller serviceProcessInstaller = 
#                                new ServiceProcessInstaller();
#             ServiceInstaller serviceInstaller = new ServiceInstaller();
#             serviceProcessInstaller.Account = ServiceAccount.LocalSystem;
#             serviceProcessInstaller.Username = null;
#             serviceProcessInstaller.Password = null;
#             serviceInstaller.DisplayName = "Set Timer Resolution Service";
#             serviceInstaller.StartType = ServiceStartMode.Automatic;
#             serviceInstaller.ServiceName = "STR";
#             this.Installers.Add(serviceProcessInstaller);
#             this.Installers.Add(serviceInstaller);
#         }
#     }
# }
# "@
# Set-Content -Path "$env:C:\Windows\SetTimerResolutionService.cs" -Value $MultilineComment -Force
# # compile and create service
# Start-Process -Wait "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" -ArgumentList "-out:C:\Windows\SetTimerResolutionService.exe C:\Windows\SetTimerResolutionService.cs" -WindowStyle Hidden
# # delete file
# Remove-Item "$env:C:\Windows\SetTimerResolutionService.cs" -ErrorAction SilentlyContinue | Out-Null
# # install and start service
# New-Service -Name "Set Timer Resolution Service" -BinaryPathName "$env:C:\Windows\SetTimerResolutionService.exe" -ErrorAction SilentlyContinue | Out-Null
# Set-Service -Name "Set Timer Resolution Service" -StartupType Automatic -ErrorAction SilentlyContinue | Out-Null
# Set-Service -Name "Set Timer Resolution Service" -Status Running -ErrorAction SilentlyContinue | Out-Null
# # fix timer resolution regedit
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "GlobalTimerResolutionRequests" /t REG_DWORD /d "1" /f | Out-Null
# Write-Host "Done."  -ForegroundColor Green
# Write-Host "Restart your computer for settings to take effect." -ForegroundColor Red
# pause