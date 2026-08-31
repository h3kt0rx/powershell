#requires -version 5.1

<#
.SYNOPSIS
    Lists installed applications while excluding Windows updates
    and common Windows/system components.

.DESCRIPTION
    Reads the Windows Uninstall registry instead of Win32_Product.

    Checks:
      - 64-bit machine-wide applications
      - 32-bit machine-wide applications
      - Per-user applications

    Excludes:
      - Windows Updates
      - Hotfixes
      - Security Updates
      - Drivers
      - Windows components
      - Runtimes
      - Frameworks
      - Redistributables
      - SDKs
      - Language packs
      - System components

    Outputs the results to:
      Desktop\installed-programs.txt

.NOTES
    Does not require Administrator privileges.
#>

$RegistryPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

# -----------------------------------------------------------------------
# Get uninstall entries
# -----------------------------------------------------------------------

$RawPrograms = foreach ($Path in $RegistryPaths) {
    Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
}

# -----------------------------------------------------------------------
# Process applications
# -----------------------------------------------------------------------

$Programs = foreach ($Program in $RawPrograms) {

    # Must have a name
    if ([string]::IsNullOrWhiteSpace($Program.DisplayName)) {
        continue
    }

    # Exclude entries explicitly marked as system components
    if ($Program.SystemComponent -eq 1) {
        continue
    }

    # Exclude entries without an uninstall command
    if (
        [string]::IsNullOrWhiteSpace($Program.UninstallString) -and
        [string]::IsNullOrWhiteSpace($Program.QuietUninstallString)
    ) {
        continue
    }

    $Name = $Program.DisplayName
    $Publisher = $Program.Publisher
    $ReleaseType = $Program.ReleaseType

    # -------------------------------------------------------------------
    # Windows Updates / Hotfixes
    # -------------------------------------------------------------------

    if ($Name -match '^(KB\d+|Update for |Security Update|Hotfix for |Windows Update)') {
        continue
    }

    if ($ReleaseType -match 'Update|Hotfix|Security Update|Service Pack|Language Pack') {
        continue
    }

    # -------------------------------------------------------------------
    # Windows components
    # -------------------------------------------------------------------

    if ($Name -match '^(Microsoft Windows|Windows Driver|Windows Software Development Kit|Windows Assessment and Deployment Kit)') {
        continue
    }

    # -------------------------------------------------------------------
    # Drivers
    # -------------------------------------------------------------------

    if ($Name -match '(Driver|Drivers|Driver Package|Device Software)') {
        continue
    }

    # -------------------------------------------------------------------
    # .NET / runtimes / frameworks
    # -------------------------------------------------------------------

    if ($Name -match '^(\.NET|Microsoft \.NET)') {
        continue
    }

    if ($Name -match 'Visual C\+\+.*Redistributable') {
        continue
    }

    if ($Name -match 'Visual Studio.*(Runtime|Tools|Redistributable)') {
        continue
    }

    if ($Name -match 'Microsoft Edge WebView2') {
        continue
    }

    if ($Name -match 'Microsoft Windows Desktop Runtime') {
        continue
    }

    if ($Name -match 'ASP\.NET Core Runtime') {
        continue
    }

    # -------------------------------------------------------------------
    # Development components
    # -------------------------------------------------------------------

    if ($Name -match '(Redistributable|Runtime Environment|SDK|Development Kit|Developer Pack|Targeting Pack)') {
        continue
    }

    # -------------------------------------------------------------------
    # Microsoft SQL Server system infrastructure
    # -------------------------------------------------------------------

    if ($Name -match '^Microsoft SQL Server.*(Native Client|Setup|Browser|LocalDB|Compact)') {
        continue
    }

    # -------------------------------------------------------------------
    # Language packs
    # -------------------------------------------------------------------

    if ($Name -match '(Language Pack|Language Experience Pack|Proofing Tools)') {
        continue
    }

    # -------------------------------------------------------------------
    # Microsoft system applications
    # -------------------------------------------------------------------

    if ($Publisher -match '^(Microsoft Corporation|Microsoft Windows)$') {
        continue
    }

    # -------------------------------------------------------------------
    # Format installation date
    # -------------------------------------------------------------------

    $InstallDate = $Program.InstallDate

    if ($InstallDate -match '^\d{8}$') {
        try {
            $InstallDate = [datetime]::ParseExact(
                $InstallDate,
                'yyyyMMdd',
                $null
            ).ToString('yyyy-MM-dd')
        }
        catch {
            # Leave original value if it cannot be parsed
        }
    }

    # -------------------------------------------------------------------
    # Return application object
    # -------------------------------------------------------------------

    [PSCustomObject]@{
        Name            = $Name
        Version         = $Program.DisplayVersion
        Publisher       = $Publisher
        InstallDate     = $InstallDate
        InstallLocation = $Program.InstallLocation
    }
}

# -----------------------------------------------------------------------
# Remove duplicates and sort
# -----------------------------------------------------------------------

$Programs = @(
    $Programs |
        Sort-Object Name, Version, Publisher -Unique
)

# -----------------------------------------------------------------------
# Create output file
# -----------------------------------------------------------------------

$OutputFile = Join-Path $env:USERPROFILE 'Desktop\installed-programs.txt'

# -----------------------------------------------------------------------
# Build text output
# -----------------------------------------------------------------------

$Output = @()

$Output += 'Installed Applications'
$Output += '======================='
$Output += ''
$Output += "Computer: $env:COMPUTERNAME"
$Output += "User:     $env:USERNAME"
$Output += "Date:     $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$Output += ''

if ($Programs.Count -eq 0) {

    $Output += 'No applications found.'

}
else {

    # Create a clean table for the text file
    $Table = $Programs |
        Sort-Object Name |
        Format-Table Name, Version, Publisher, InstallDate -AutoSize |
        Out-String -Width 240

    $Output += $Table.TrimEnd()

}

$Output += ''
$Output += "Total applications found: $($Programs.Count)"

# -----------------------------------------------------------------------
# Write text file
# -----------------------------------------------------------------------

$Output |
    Out-File -FilePath $OutputFile -Encoding UTF8

# -----------------------------------------------------------------------
# Display results
# -----------------------------------------------------------------------

Write-Host ''
Write-Host 'Installed Applications' -ForegroundColor Cyan
Write-Host '=======================' -ForegroundColor Cyan
Write-Host ''

if ($Programs.Count -eq 0) {

    Write-Host 'No applications found.' -ForegroundColor Yellow

}
else {

    $Programs |
        Sort-Object Name |
        Format-Table Name, Version, Publisher, InstallDate -AutoSize

}

Write-Host ''
Write-Host "Total applications found: $($Programs.Count)" -ForegroundColor Cyan
Write-Host ''
Write-Host "Results saved to:" -ForegroundColor Green
Write-Host $OutputFile -ForegroundColor Green
Pause
