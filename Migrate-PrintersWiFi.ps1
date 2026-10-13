#Requires -Version 5.1
<#
.SYNOPSIS
    Export / Import printers (with printer drivers only) and saved Wi-Fi profiles
    for a Windows 11 -> Windows 11 migration.

.NOTES
    Run from an ELEVATED PowerShell window.
    Works with:  iwr -useb <raw github url> | iex

    Folder layout created on export:
      <folder you pick>\
        Migration_yyyy-MM-dd_HH-mm-ss\
          Printers\   (printers.printerExport, printers.csv, ports.csv, drivers.csv)
          WiFi\       (one XML per profile + wifi_passwords.csv)

    Printer export/import uses Microsoft's PrintBrm.exe, which only packages the
    drivers used by your print queues (printer drivers only - nothing else).
#>

$ErrorActionPreference = 'Stop'

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Select-FolderDialog {
    param([string]$Description)
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = $Description
        $dlg.ShowNewFolderButton = $true
        $owner = New-Object System.Windows.Forms.Form -Property @{ TopMost = $true }
        if ($dlg.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {
            return $dlg.SelectedPath
        }
        return $null
    }
    catch {
        $p = Read-Host "$Description (type full path)"
        if ($p) { return $p.Trim('"') }
        return $null
    }
}

$PrintBrm = Join-Path $env:SystemRoot 'System32\spool\tools\PrintBrm.exe'

# ---------------------------------------------------------------- EXPORT ---
function Export-Migration {
    $base = Select-FolderDialog 'Select the main folder to save the migration into'
    if (-not $base) { Write-Warning 'No folder selected. Cancelled.'; return }

    $stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $root  = Join-Path $base "Migration_$stamp"
    $pDir  = Join-Path $root 'Printers'
    $wDir  = Join-Path $root 'WiFi'
    New-Item -ItemType Directory -Path $pDir, $wDir -Force | Out-Null
    Write-Host "`nExporting to: $root" -ForegroundColor Cyan

    # ---- Printers ----
    Write-Host "`n[Printers] Exporting queues, ports and printer drivers..." -ForegroundColor Yellow
    try {
        Get-Printer | Select-Object Name, DriverName, PortName, Shared, ShareName, Location, Comment |
            Export-Csv (Join-Path $pDir 'printers.csv') -NoTypeInformation
        Get-PrinterPort | Select-Object Name, PrinterHostAddress, PortNumber, Description |
            Export-Csv (Join-Path $pDir 'ports.csv') -NoTypeInformation
        Get-PrinterDriver | Select-Object Name, Manufacturer, PrinterEnvironment, MajorVersion, InfPath |
            Export-Csv (Join-Path $pDir 'drivers.csv') -NoTypeInformation
    }
    catch { Write-Warning "Could not write reference CSVs: $($_.Exception.Message)" }

    if (Test-Path $PrintBrm) {
        $file = Join-Path $pDir 'printers.printerExport'
        & $PrintBrm -B -F $file | Out-Host
        if ($LASTEXITCODE -eq 0 -and (Test-Path $file)) {
            Write-Host '[Printers] Export complete.' -ForegroundColor Green
        } else {
            Write-Warning "PrintBrm exited with code $LASTEXITCODE. Printer export may have failed."
        }
    } else {
        Write-Warning "PrintBrm.exe not found at $PrintBrm. Skipped printer export."
    }

    # ---- Wi-Fi ----
    Write-Host "`n[Wi-Fi] Exporting saved profiles..." -ForegroundColor Yellow
    netsh wlan export profile key=clear folder="$wDir" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning 'No Wi-Fi adapter / WLAN service found, or export failed.'
    } else {
        $rows = foreach ($f in Get-ChildItem $wDir -Filter *.xml) {
            try {
                $x = [xml](Get-Content $f.FullName -Raw)
                [pscustomobject]@{
                    SSID     = $x.WLANProfile.SSIDConfig.SSID.name
                    Auth     = $x.WLANProfile.MSM.security.authEncryption.authentication
                    Password = $x.WLANProfile.MSM.security.sharedKey.keyMaterial
                    File     = $f.Name
                }
            } catch { }
        }
        $rows | Export-Csv (Join-Path $wDir 'wifi_passwords.csv') -NoTypeInformation
        Write-Host "[Wi-Fi] Exported $(@($rows).Count) profile(s)." -ForegroundColor Green
        $rows | Format-Table SSID, Password -AutoSize | Out-Host
    }

    Write-Host "`nDone. Migration folder: $root" -ForegroundColor Green
    Write-Warning 'The WiFi XML files and wifi_passwords.csv contain passwords in PLAIN TEXT. Protect or delete them after migrating.'
}

# ---------------------------------------------------------------- IMPORT ---
function Import-Migration {
    $base = Select-FolderDialog 'Select the main folder that holds your Migration_* folders (or a Migration_* folder itself)'
    if (-not $base) { Write-Warning 'No folder selected. Cancelled.'; return }

    # If they picked a migration folder directly, use it
    if ((Test-Path (Join-Path $base 'Printers')) -or (Test-Path (Join-Path $base 'WiFi'))) {
        $root = $base
    }
    else {
        $folders = @(Get-ChildItem $base -Directory -Filter 'Migration_*' | Sort-Object Name -Descending)
        if ($folders.Count -eq 0) { Write-Warning "No Migration_* folders found in $base"; return }

        Write-Host "`nAvailable migration folders:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $folders.Count; $i++) {
            Write-Host ("  [{0}] {1}" -f ($i + 1), $folders[$i].Name)
        }
        $sel = Read-Host "`nSelect a folder number (default 1 = newest)"
        if ([string]::IsNullOrWhiteSpace($sel)) { $sel = 1 }
        if ($sel -notmatch '^\d+$' -or [int]$sel -lt 1 -or [int]$sel -gt $folders.Count) {
            Write-Warning 'Invalid selection.'; return
        }
        $root = $folders[[int]$sel - 1].FullName
    }
    Write-Host "`nImporting from: $root" -ForegroundColor Cyan

    # ---- Printers ----
    $pDir = Join-Path $root 'Printers'
    $exp  = Get-ChildItem $pDir -Filter *.printerExport -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($exp -and (Test-Path $PrintBrm)) {
        Write-Host "`n[Printers] Restoring printers and their drivers (printer drivers only)..." -ForegroundColor Yellow
        Start-Service Spooler -ErrorAction SilentlyContinue
        & $PrintBrm -R -F $exp.FullName -O FORCE | Out-Host
        if ($LASTEXITCODE -eq 0) {
            Write-Host '[Printers] Import complete.' -ForegroundColor Green
        } else {
            Write-Warning "PrintBrm exited with code $LASTEXITCODE. Check output above."
        }
    } else {
        Write-Warning '[Printers] No .printerExport file found (or PrintBrm missing). Skipped.'
    }

    # ---- Wi-Fi ----
    $wDir = Join-Path $root 'WiFi'
    $xmls = @(Get-ChildItem $wDir -Filter *.xml -ErrorAction SilentlyContinue)
    if ($xmls.Count -gt 0) {
        Write-Host "`n[Wi-Fi] Importing $($xmls.Count) profile(s)..." -ForegroundColor Yellow
        foreach ($x in $xmls) {
            netsh wlan add profile filename="$($x.FullName)" user=all | Out-Host
        }
    } else {
        Write-Warning '[Wi-Fi] No profile XML files found. Skipped.'
    }

    Write-Host "`nImport finished." -ForegroundColor Green
}

# ------------------------------------------------------------------ MAIN ---
if (-not (Test-IsAdmin)) {
    Write-Warning 'Please run this from an elevated (Run as administrator) PowerShell window.'
    return
}

Write-Host '=== Printer + Wi-Fi Migration ===' -ForegroundColor Cyan
Write-Host '  [1] Export (old laptop)'
Write-Host '  [2] Import (new laptop)'
$choice = Read-Host 'Choose 1 or 2 (or type Export / Import)'

switch -Regex ($choice) {
    '^(1|e|export)$' { Export-Migration }
    '^(2|i|import)$' { Import-Migration }
    default          { Write-Warning 'Invalid choice. Nothing done.' }
}