# BTM-Analyzer v0.2
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2026 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2026-03-16
#
#
# ██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
# ██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
# ██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
# ██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
# ███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
# ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
#
#
# Dependencies:
#
# ImportExcel v7.8.10 (2024-10-21)
# https://github.com/dfinke/ImportExcel
#
#
# Changelog:
# Version 0.1
# Release Date: 2025-11-20
# Initial Release
#
# Version 0.2
# Release Date: 2025-12-11
# Added: Cross-platform support for macOS and Windows
#
#
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.6456) and PowerShell 5.1 (5.1.19041.6456)
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.6456) and PowerShell 7.5.5
# Tested on macOS with PowerShell 7.x
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  BTM-Analyzer v0.2 - Automated Forensic Analysis of BTM Dump File

.DESCRIPTION
  BTM-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of the dumped BTM database (Background Task Management --> Persistence).

  GUI: System Settings > General > Login Items & Extensions

  CLI: sudo sfltool dumpbtm > ~/Desktop/btm.txt

.PARAMETER OutputDir
  Specifies the output directory. Default is "$HOME/Desktop/BTM-Analyzer" (macOS) or "$env:USERPROFILE\Desktop\BTM-Analyzer" (Windows).

  Note: The subdirectory 'BTM-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the input file (btm.txt).

.EXAMPLE
  PS> ./BTM-Analyzer.ps1

.EXAMPLE
  PS> ./BTM-Analyzer.ps1 -Path "$HOME/Desktop/btm.txt"

.EXAMPLE
  PS> ./BTM-Analyzer.ps1 -Path "/path/to/btm.txt" -OutputDir "/path/to/output"

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region CmdletBinding

[CmdletBinding()]
Param(
    [String]$Path,
    [String]$OutputDir,
    [switch]$NoExcel = $true
)

#endregion CmdletBinding

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Initialisations

# Set Progress Preference to Silently Continue
$OriginalProgressPreference = $Global:ProgressPreference
$Global:ProgressPreference = 'SilentlyContinue'

#endregion Initialisations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Declarations

# Declarations

# Script Root
if ($PSVersionTable.PSVersion.Major -gt 2)
{
    # PowerShell 3+
    $SCRIPT_DIR = $PSScriptRoot
}
else
{
    # PowerShell 2
    $SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

# Export-Csv: @CsvArgs is required on Windows PowerShell 5.1 and obsolete (warns) on PowerShell 7.4+
$script:CsvArgs = @{}
if ($PSVersionTable.PSVersion.Major -lt 6) { $script:CsvArgs.NoTypeInformation = $true }

# Detect Operating System
# NOTE: Do NOT use names like IsWindows/IsMacOS/IsLinux here because PowerShell defines read-only automatic variables with those names.
$script:OnWindows = $false
$script:OnMacOS   = $false
$script:OnLinux   = $false

if ($PSVersionTable.PSVersion.Major -ge 6)
{
    $script:OnWindows = $IsWindows
    $script:OnMacOS   = $IsMacOS
    $script:OnLinux   = $IsLinux
}
else
{
    # Windows PowerShell 5.1
    $script:OnWindows = $true
}

# Excel export toggle (optional)
$script:EnableExcel = $false
if (-not $NoExcel -and (Get-Module -ListAvailable -Name ImportExcel))
{
    $script:EnableExcel = $true
}

# Colors / Styling (XLSX only)
Add-Type -AssemblyName System.Drawing
$script:Green  = [System.Drawing.Color]::FromArgb(0,176,80)
$script:Orange = [System.Drawing.Color]::FromArgb(255,192,0)
$script:UseExcelStyling = [bool]$script:EnableExcel

# Output Directory
if (!($OutputDir))
{
    if ($script:OnMacOS -or $script:OnLinux)
    {
        $script:OUTPUT_FOLDER = "$HOME/Desktop/BTM-Analyzer"
    }
    else
    {
        $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\BTM-Analyzer"
    }
}
else
{
    # Validate path - accept both Windows and Unix paths
    if ($OutputDir -cnotmatch '.+(?=[/\\])' -and $OutputDir -notmatch '^[/~]') 
    {
        Write-Host "[Error] You must provide a valid directory path." -ForegroundColor Red
        Exit
    }
    else
    {
        $script:OUTPUT_FOLDER = Join-Path $OutputDir "BTM-Analyzer"
    }
}

# Configuration File (JSON)
$ConfigPath = Join-Path $PSScriptRoot "Config.json"
if(!(Test-Path $ConfigPath))
{
    Write-Host "[Error] Config.json NOT found." -ForegroundColor Red
    Exit
}
else
{
    $Config = Get-Content $ConfigPath | ConvertFrom-Json

    # BackgroundColor
    if ($Config.ImportExcel.BackgroundColor)
    {
        if ($Config.ImportExcel.BackgroundColor -cnotmatch '^(([0-1]?[0-9]?[0-9])|([2][0-4][0-9])|(25[0-5])),(([0-1]?[0-9]?[0-9])|([2][0-4][0-9])|(25[0-5])),(([0-1]?[0-9]?[0-9])|([2][0-4][0-9])|(25[0-5]))$')
        {
            Write-Host "[Error] You must provide a valid RGB Color Code." -ForegroundColor Red
            Return
        }
    }

    # Excel - Color Scheme (only used for styling on Windows)
    if ($script:UseExcelStyling)
    {
        $rgbValues = $Config.ImportExcel.BackgroundColor -split ','
        $script:BackgroundColor = [System.Drawing.Color]::FromArgb([int]$rgbValues[0], [int]$rgbValues[1], [int]$rgbValues[2])
        $script:FontColor = $Config.ImportExcel.FontColor
    }
}

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

Function Header {

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "BTM-Analyzer v0.2 - Automated Forensic Analysis of BTM Dump File"

# Check if the PowerShell script is being run with elevated privileges
if ($script:OnMacOS -or $script:OnLinux)
{
    # On macOS/Linux, check if running as root or with sudo
    $currentUser = & id -u
    if ($currentUser -ne "0")
    {
        Write-Host "[Warning] This script may require elevated privileges (sudo) for some operations." -ForegroundColor Yellow
    }
}
else
{
    # Windows admin check
    if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        Write-Host "[Error] This PowerShell script must be run with admin rights." -ForegroundColor Red
        Exit
    }
}

# ImportExcel is optional
if (-not $script:EnableExcel)
{
    if ($NoExcel)
    {
        if ($PSBoundParameters.ContainsKey('NoExcel'))
        {
            Write-Host "[Info]  -NoExcel specified. XLSX output will be skipped." -ForegroundColor Yellow
        }
        else
        {
            Write-Host "[Info]  XLSX output is disabled by default. CSV output will be created." -ForegroundColor Yellow
            Write-Host "[Info]  To enable XLSX (optional): install ImportExcel and run with -NoExcel:`$false" -ForegroundColor Yellow
        }
    }
    else
    {
        Write-Host "[Info]  ImportExcel not installed. XLSX output will be skipped." -ForegroundColor Yellow
        Write-Host "[Info]  Install (optional): Install-Module -Name ImportExcel -Scope CurrentUser" -ForegroundColor Yellow
    }
}

# Flush Output Directory
if (Test-Path "$OUTPUT_FOLDER")
{
    Get-ChildItem -Path "$OUTPUT_FOLDER" -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse
    New-Item "$OUTPUT_FOLDER" -ItemType Directory -Force | Out-Null
}
else 
{
    New-Item "$OUTPUT_FOLDER" -ItemType Directory -Force | Out-Null
}

# Function Get-FileSize
Function script:Get-FileSize
{
    Param ([long]$Length)
    If ($Length -gt 1TB) {[string]::Format("{0:0.00} TB", $Length / 1TB)}
    ElseIf ($Length -gt 1GB) {[string]::Format("{0:0.00} GB", $Length / 1GB)}
    ElseIf ($Length -gt 1MB) {[string]::Format("{0:0.00} MB", $Length / 1MB)}
    ElseIf ($Length -gt 1KB) {[string]::Format("{0:0.00} KB", $Length / 1KB)}
    ElseIf ($Length -gt 0) {[string]::Format("{0:0.00} Bytes", $Length)}
    Else {""}
}

# Select BTM Dump (btm.txt)
if(!($Path))
{
    if ($script:OnWindows)
    {
        # Windows - Use OpenFileDialog
        Add-Type -AssemblyName System.Windows.Forms
        Function Get-LogFile($InitialDirectory)
        { 
            [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
            $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $OpenFileDialog.InitialDirectory = $InitialDirectory
            $OpenFileDialog.Filter = "BTM Dump|btm.txt|All Files (*.*)|*.*"
            $OpenFileDialog.ShowDialog()
            $OpenFileDialog.Filename
            $OpenFileDialog.ShowHelp = $true
            $OpenFileDialog.Multiselect = $false
        }

        $Result = Get-LogFile

        if($Result -eq "OK")
        {
            $script:LogFile = $Result[1]
        }
        else
        {
            $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
            Exit
        }
    }
    else
    {
        # macOS/Linux - Prompt for path (keep simple for .txt; no chooser required)
        Write-Host ""
        Write-Host "[Info]  Please provide the path to the BTM dump file (btm.txt)." -ForegroundColor Cyan
        Write-Host "[Info]  Generate with: sudo sfltool dumpbtm > ~/Desktop/btm.txt" -ForegroundColor Cyan
        Write-Host ""
        $script:LogFile = Read-Host "Enter path to btm.txt"
        
        if ([string]::IsNullOrWhiteSpace($script:LogFile))
        {
            Write-Host "[Error] No path provided." -ForegroundColor Red
            Exit
        }
        
        # Expand ~ to home directory
        if ($script:LogFile.StartsWith("~"))
        {
            $script:LogFile = $script:LogFile.Replace("~", $HOME)
        }
    }
}
else
{
    $script:LogFile = $Path
    # Expand ~ to home directory
    if ($script:LogFile.StartsWith("~"))
    {
        $script:LogFile = $script:LogFile.Replace("~", $HOME)
    }
}

# Create a record of your PowerShell session to a text file
Start-Transcript -Path "$OUTPUT_FOLDER/Transcript.txt"

# Get Start Time
$script:startTime = (Get-Date)

# Logo
$Logo = @"
██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
"@

Write-Output ""
Write-Output "$Logo"
Write-Output ""

# Header
Write-Output "BTM-Analyzer v0.2 - Automated Forensic Analysis of BTM Dump File for DFIR"
Write-Output "(c) 2026 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Analysis date (ISO 8601)
$AnalysisDate = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "Analysis date: $AnalysisDate UTC"
Write-Output ""

}

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Analysis

# BTM Dump - App Background Activity (Persistence)

# BTM, or Background Task Management, is a macOS framework that manages login and background items, which are applications that run tasks after you log in. 
# It's handled by the BackgroundTaskManagementAgent and helps users and administrators control and see what's running in the background.

# Background Managed Tasks --> Background Agents, Daemons, & Login Items

# Location / Database Path (macOS 13+)
# /private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm

# Aftermath Source:
# Aftermath Collection\Persistence\btm.txt

Function Invoke-Processing {

# Input-Check
if (!(Test-Path "$LogFile" -PathType Leaf))
{
    Write-Host "[Error] $LogFile does not exist." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check File Extension
$Extension = [IO.Path]::GetExtension($LogFile)
if (!($Extension -eq ".txt" ))
{
    Write-Host "[Error] No TXT File provided." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

$FileName = [IO.Path]::GetFileName($LogFile)
Write-Output "[Info]  Processing Background Task Management Dump File ($FileName) ..."
New-Item "$OUTPUT_FOLDER/CSV" -ItemType Directory -Force | Out-Null
if ($script:EnableExcel)
{
    New-Item "$OUTPUT_FOLDER/XLSX" -ItemType Directory -Force | Out-Null
}

# MD5 Hash
$MD5 = (Get-FileHash -LiteralPath "$LogFile" -Algorithm MD5).Hash
Write-Output "[Info]  MD5 Hash: $MD5"

# SHA1 Hash
$SHA1 = (Get-FileHash -LiteralPath "$LogFile" -Algorithm SHA1).Hash
Write-Output "[Info]  SHA1 Hash: $SHA1"

# SHA256 Hash
$SHA256 = (Get-FileHash -LiteralPath "$LogFile" -Algorithm SHA256).Hash
Write-Output "[Info]  SHA256 Hash: $SHA256"

# Input Size
$InputSize = Get-FileSize((Get-Item "$LogFile").Length)
Write-Output "[Info]  Total Input Size: $InputSize"

# Count rows of TXT (w/ thousands separators)
[int]$TotalLines = 0
$Reader = New-Object IO.StreamReader "$LogFile"
while($Reader.ReadLine() -ne $null){ $TotalLines++ }
($Reader.Dispose())
$Rows = '{0:N0}' -f $TotalLines | ForEach-Object {$_ -replace ' ','.'}
Write-Output "[Info]  Total Lines: $Rows"

# Count User IDs
$Count = (Get-Content "$LogFile" | Select-String -Pattern "Records for UID" | Measure-Object).Count
Write-Output "[Info]  $Count User ID's found"

# Count Background Items (Item Records)
$Total = (Get-Content "$LogFile" | Select-String -Pattern "^ #\d+:" | Measure-Object).Count
Write-Output "[Info]  $Total Background Item(s) found"

# Background Items per User
New-Item "$OUTPUT_FOLDER/Users" -ItemType Directory -Force | Out-Null
$Objects = (Get-Content "$LogFile" -Raw) -split "`n`n`n" | Where-Object { $_ -match "========================" }
ForEach ($Object in $Objects) {
    $UID = $Object.Split("`n`n") | Select-String -Pattern "Records for UID" | ForEach-Object{($_ -split "\s+")[4]}
    $Object | Out-File "$OUTPUT_FOLDER/Users/$UID.txt" -Encoding UTF8
}

# User ID's (UID)
#  -2 = Appears to be a composite covering most Background Items
#   0 = Root
# 501 = Primary Admin User

# List all UIDs
# dscl . -list /Users UniqueID

# Item Details
$Objects = (Get-Content "$LogFile" -Raw) -split "`n`n`n"

# CSV
$Results = [Collections.Generic.List[PSObject]]::new()
ForEach($Object in $Objects)
{
    $UID = $Object.Split("`n`n") | Select-String -Pattern "Records for UID" | ForEach-Object{($_ -split "\s+")[4]}
    $Items = $Object | ForEach-Object { $_ -split("`n`n") } | Where-Object { $_ -match "^ #\d+:" }

    ForEach($Item in $Items)
    {
        $EmbeddedItems = ($Item.Split("`n`n") | Select-String -Pattern "^    #\d+:" | ForEach-Object { $_ -replace "^    " }) -join "`r`n"

        $Line = [PSCustomObject]@{
        "UID"               = $UID
        "Item ID"           = $Item.Split("`n`n") | Select-String -Pattern "^ #" | ForEach-Object { $_ -replace ":.*" } | ForEach-Object { $_ -replace ".*#" }
        "UUID"              = $Item.Split("`n`n") | Select-String -Pattern "UUID:" | ForEach-Object{($_ -split "\s+")[2]}
        "Name"              = $Item.Split("`n`n") | Select-String -Pattern "  Name:" | ForEach-Object { $_ -replace ".*Name: " }
        "Developer Name"    = $Item.Split("`n`n") | Select-String -Pattern "Developer Name:" | ForEach-Object { $_ -replace ".*Developer Name: " }
        "Team Identifier"   = $Item.Split("`n`n") | Select-String -Pattern "Team Identifier:" | ForEach-Object { $_ -replace ".*Team Identifier: " }
        "Type"              = $Item.Split("`n`n") | Select-String -Pattern "Type:" | ForEach-Object { $_ -replace ".*Type: " }
        "Flags"             = $Item.Split("`n`n") | Select-String -Pattern "Flags:" | ForEach-Object { $_ -replace ".*Flags: " }
        "Disposition"       = $Item.Split("`n`n") | Select-String -Pattern "Disposition:" | ForEach-Object { $_ -replace ".*Disposition: " }
        "Identifier"        = $Item.Split("`n`n") | Select-String -Pattern "  Identifier:" | ForEach-Object { $_ -replace ".*Identifier: " }
        "URL"               = $Item.Split("`n`n") | Select-String -Pattern "URL:" | ForEach-Object { $_ -replace ".*URL: " }
        "Executable Path"   = $Item.Split("`n`n") | Select-String -Pattern "Executable Path:" | ForEach-Object { $_ -replace ".*Executable Path: " }
        "Generation"        = $Item.Split("`n`n") | Select-String -Pattern "Generation:" | ForEach-Object { $_ -replace ".*Generation: " }
        "Assoc. Bundle IDs" = $Item.Split("`n`n") | Select-String -Pattern "Assoc. Bundle IDs:" | ForEach-Object { $_ -replace ".*Assoc. Bundle IDs: " } | ForEach-Object { $_ -replace "\[ " } | ForEach-Object { $_ -replace " \]" }
        "Bundle Identifier" = $Item.Split("`n`n") | Select-String -Pattern "Bundle Identifier:" | ForEach-Object { $_ -replace ".*Bundle Identifier: " }
        "Embedded Item Identifiers" = $EmbeddedItems
        "Parent Identifier" = $Item.Split("`n`n") | Select-String -Pattern "Parent Identifier:" | ForEach-Object { $_ -replace ".*Parent Identifier: " }
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER/CSV/BTM.csv" @CsvArgs -Encoding UTF8
}

# XLSX
if ($script:EnableExcel -and (Test-Path "$OUTPUT_FOLDER/CSV/BTM.csv"))
{
    if ((Get-Item "$OUTPUT_FOLDER/CSV/BTM.csv").Length -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER/CSV/BTM.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER/XLSX/BTM.xlsx" -NoHyperLinkConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Background Items" -CellStyleSB {
        param($WorkSheet)
        if ($script:UseExcelStyling)
        {
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:Q1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-K and M-Q
            $WorkSheet.Cells["A:K"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["M:Q"].Style.HorizontalAlignment="Center"
        }
        }
    }
}

}

#endregion Analysis

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Statistics

Function Get-Statistics {

# Stats
New-Item "$OUTPUT_FOLDER/Stats" -ItemType Directory -Force | Out-Null

# Data Import
$BTM = Import-Csv "$OUTPUT_FOLDER/CSV/BTM.csv" -Delimiter "," -Encoding UTF8

# Developer Name (Stats)
$Total = ($BTM | Select-Object "Developer Name" | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $BTM | Group-Object "Developer Name" | Select-Object @{Name='Developer Name'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    if ($script:EnableExcel)
    {
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER/Stats/DeveloperName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Developer Name" -CellStyleSB {
        param($WorkSheet)
        if ($script:UseExcelStyling)
        {
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-C
            $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        }
        }
    }
    else
    {
        $Stats | Export-Csv -Path "$OUTPUT_FOLDER/Stats/DeveloperName.csv" @CsvArgs -Encoding UTF8
    }
}

# Name (Stats)
$Total = ($BTM | Select-Object Name | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $BTM | Group-Object Name | Select-Object @{Name='Name'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    if ($script:EnableExcel)
    {
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER/Stats/Name.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Name" -CellStyleSB {
        param($WorkSheet)
        if ($script:UseExcelStyling)
        {
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-C
            $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        }
        }
    }
    else
    {
        $Stats | Export-Csv -Path "$OUTPUT_FOLDER/Stats/Name.csv" @CsvArgs -Encoding UTF8
    }
}

# Name / Developer Name (Stats)
$Total = ($BTM | Select-Object Name | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $BTM | Group-Object Name,"Developer Name" | Select-Object @{Name='Name'; Expression={ $_.Values[0] }},@{Name='Developer Name'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    if ($script:EnableExcel)
    {
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER/Stats/Name-DeveloperName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Name - Developer Name" -CellStyleSB {
        param($WorkSheet)
        if ($script:UseExcelStyling)
        {
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-D
            $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
        }
        }
    }
    else
    {
        $Stats | Export-Csv -Path "$OUTPUT_FOLDER/Stats/Name-DeveloperName.csv" @CsvArgs -Encoding UTF8
    }
}

# Type (Stats)
$Total = ($BTM | Select-Object Type | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $BTM | Group-Object Type | Select-Object @{Name='Type'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    if ($script:EnableExcel)
    {
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER/Stats/Type.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Type" -CellStyleSB {
        param($WorkSheet)
        if ($script:UseExcelStyling)
        {
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-C
            $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        }
        }
    }
    else
    {
        $Stats | Export-Csv -Path "$OUTPUT_FOLDER/Stats/Type.csv" @CsvArgs -Encoding UTF8
    }
}

# Type Flags
#    0x2  = App
#    0x4  = Login Item
#    0x20 = Developer
#    0x40 = Spotlight
#   0x800 = Quicklook
# 0x10008 = Legacy Agent
# 0x10010 = Legacy Daemon

# 0x1  = User Item
# 0x8  = Agent
# 0x10 = Daemon

}

#endregion Statistics

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Footer

Function Footer {

# Get End Time
$endTime = (Get-Date)

# Echo Time elapsed
Write-Output ""
Write-Output "FINISHED!"

$Time = ($endTime-$startTime)
$ElapsedTime = ('Overall analysis duration: {0} h {1} min {2} sec' -f $Time.Hours, $Time.Minutes, $Time.Seconds)
Write-Output "$ElapsedTime"

# Stop logging
Write-Host ""
Stop-Transcript
Start-Sleep 0.5

# Show completion message
if ($script:OnWindows)
{
    # Windows - Use MessageBox
    Add-Type -AssemblyName System.Windows.Forms
    $MessageBody = "Status: BTM Analysis completed."
    $MessageTitle = "BTM-Analyzer.ps1 (https://lethal-forensics.com/)"
    $ButtonType = "OK"
    $MessageIcon = "Information"
    $Result = [System.Windows.Forms.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon)

    if ($Result -eq "OK" ) 
    {
        $Global:ProgressPreference = $OriginalProgressPreference
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }
}
else
{
    # macOS/Linux - Console message
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  BTM Analysis completed successfully!  " -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Output directory: $OUTPUT_FOLDER" -ForegroundColor Cyan
    Write-Host ""
    
    $Global:ProgressPreference = $OriginalProgressPreference
}

}

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# Main
Header
Invoke-Processing
Get-Statistics
Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################
