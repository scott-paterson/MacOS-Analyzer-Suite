# Quarantine-Analyzer v0.3
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2025 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2025-11-20
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
# SQLite Tools
# Windows: https://sqlite.org/download.html
# macOS: Built-in (sqlite3)
#
#
# Changelog:
# Version 0.1
# Release Date: 2024-06-22
# Initial Release
#
# Version 0.2
# Release Date: 2024-11-20
# Fixed: Minor Bug Fixes and Improvements
#
# Version 0.3
# Release Date: 2025-12-11
# Added: Cross-platform support for macOS and Windows
#
#
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.5011) and target PowerShell version 5.1 (5.1.19041.5007)
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.5011) and PowerShell 7.4.6
# Tested on macOS with PowerShell 7.x
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  Quarantine-Analyzer v0.3 - Automated Processing of LSQuarantine Database for DFIR

.DESCRIPTION
  Quarantine-Analyzer.ps1 is a PowerShell script utilized to simplify the processing of the LSQuarantine database (macOS quarantine events) for DFIR.

.PARAMETER OutputDir
  Specifies the output directory. Default is "$HOME/Desktop/Quarantine-Analyzer" (macOS) or "$env:USERPROFILE\Desktop\Quarantine-Analyzer" (Windows).

  Note: The subdirectory 'Quarantine-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the com.apple.LaunchServices.QuarantineEventsV2 database.

.EXAMPLE
  PS> ./Quarantine-Analyzer.ps1

.EXAMPLE
  PS> ./Quarantine-Analyzer.ps1 -Path "$HOME/Desktop/com.apple.LaunchServices.QuarantineEventsV2"

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

# Colors / Styling (only supported on Windows)
$script:UseExcelStyling = $false
if ($script:OnWindows)
{
    Add-Type -AssemblyName System.Drawing
    $script:Green  = [System.Drawing.Color]::FromArgb(0,176,80)
    $script:Orange = [System.Drawing.Color]::FromArgb(255,192,0)
    if ($script:EnableExcel)
    {
        $script:UseExcelStyling = $true
    }
}

# Output Directory
if (!($OutputDir))
{
    if ($script:OnMacOS -or $script:OnLinux)
    {
        $script:OUTPUT_FOLDER = "$HOME/Desktop/Quarantine-Analyzer"
    }
    else
    {
        $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\Quarantine-Analyzer"
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
        $script:OUTPUT_FOLDER = Join-Path $OutputDir "Quarantine-Analyzer"
    }
}

# Tools

# SQLite3
if ($script:OnMacOS -or $script:OnLinux)
{
    # Use system sqlite3
    $script:SQLite3 = (Get-Command sqlite3 -ErrorAction SilentlyContinue).Source
    if (-not $script:SQLite3)
    {
        $script:SQLite3 = "/usr/bin/sqlite3"
    }
}
else
{
    $script:SQLite3 = "$SCRIPT_DIR\Tools\SQLite\sqlite3.exe"
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
$Host.UI.RawUI.WindowTitle = "Quarantine-Analyzer v0.3 - Automated Processing of LSQuarantine Database for DFIR"

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

# Check if sqlite3 exists
if (!(Test-Path "$($SQLite3)"))
{
    Write-Host "[Error] sqlite3 NOT found." -ForegroundColor Red
    Exit
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

# macOS file picker (Explorer-like) via osascript
Function script:Select-FileMacOS {
    param(
        [string]$Prompt = "Choose a file"
    )
    try
    {
        $escapedPrompt = $Prompt.Replace('"','\"')
        $result = & osascript -e "POSIX path of (choose file with prompt `"$escapedPrompt`")" 2>$null
        if ([string]::IsNullOrWhiteSpace($result)) { return $null }
        return ($result.Trim())
    }
    catch
    {
        return $null
    }
}

# Select LSQuarantine Database
if(!($Path))
{
    if ($script:OnWindows)
    {
        # Windows - Use OpenFileDialog
        Add-Type -AssemblyName System.Windows.Forms
        Function Get-Database($InitialDirectory)
        { 
            [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
            $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $OpenFileDialog.InitialDirectory = $InitialDirectory
            $OpenFileDialog.Filter = "LSQuarantine Database|com.apple.LaunchServices.QuarantineEventsV2|All Files (*.*)|*.*"
            $OpenFileDialog.ShowDialog()
            $OpenFileDialog.Filename
            $OpenFileDialog.ShowHelp = $true
            $OpenFileDialog.Multiselect = $false
        }

        $Result = Get-Database

        if($Result -eq "OK")
        {
            $script:DatabaseFile = $Result[1]
        }
        else
        {
            $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
            Exit
        }
    }
    else
    {
        if ($script:OnMacOS)
        {
            $picked = Select-FileMacOS -Prompt "Select LSQuarantine database (QuarantineEventsV2)"
            if ($picked)
            {
                $script:DatabaseFile = $picked
            }
            else
            {
                Write-Host ""
                Write-Host "[Info]  Please provide the path to the LSQuarantine database file." -ForegroundColor Cyan
                Write-Host "[Info]  Common location:" -ForegroundColor Cyan
                Write-Host "        - ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2" -ForegroundColor Gray
                Write-Host ""
                $script:DatabaseFile = Read-Host "Enter path to database"
            }
        }
        else
        {
            # Linux - Prompt for path
            Write-Host ""
            Write-Host "[Info]  Please provide the path to the LSQuarantine database file." -ForegroundColor Cyan
            Write-Host ""
            $script:DatabaseFile = Read-Host "Enter path to database"
        }
        
        if ([string]::IsNullOrWhiteSpace($script:DatabaseFile))
        {
            Write-Host "[Error] No path provided." -ForegroundColor Red
            Exit
        }
        
        # Expand ~ to home directory
        if ($script:DatabaseFile.StartsWith("~"))
        {
            $script:DatabaseFile = $script:DatabaseFile.Replace("~", $HOME)
        }
    }
}
else
{
    $script:DatabaseFile = $Path
    # Expand ~ to home directory
    if ($script:DatabaseFile.StartsWith("~"))
    {
        $script:DatabaseFile = $script:DatabaseFile.Replace("~", $HOME)
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
Write-Output "Quarantine-Analyzer v0.3 - Automated Processing of LSQuarantine Database for DFIR"
Write-Output "(c) 2025 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
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

# LSQuarantine Database - Quarantine Events
# LSQuarantine attributes are set whenever files are downloaded from the internet or received via email/AirDrop
# Location: ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2

Function Invoke-Quarantine {

# Input-Check
if (!(Test-Path "$DatabaseFile" -PathType Leaf))
{
    Write-Host "[Error] $DatabaseFile does not exist." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

$FileName = [IO.Path]::GetFileName($DatabaseFile)
Write-Output "[Info]  Processing LSQuarantine Database ($FileName) ..."
New-Item "$OUTPUT_FOLDER/CSV" -ItemType Directory -Force | Out-Null
if ($script:EnableExcel)
{
    New-Item "$OUTPUT_FOLDER/XLSX" -ItemType Directory -Force | Out-Null
}

# MD5 Hash
$MD5 = (Get-FileHash -LiteralPath "$DatabaseFile" -Algorithm MD5).Hash
Write-Output "[Info]  MD5 Hash: $MD5"

# SHA1 Hash
$SHA1 = (Get-FileHash -LiteralPath "$DatabaseFile" -Algorithm SHA1).Hash
Write-Output "[Info]  SHA1 Hash: $SHA1"

# SHA256 Hash
$SHA256 = (Get-FileHash -LiteralPath "$DatabaseFile" -Algorithm SHA256).Hash
Write-Output "[Info]  SHA256 Hash: $SHA256"

# File Size
$FileSize = Get-FileSize((Get-Item "$DatabaseFile").Length)
Write-Output "[Info]  File Size: $FileSize"

# Copy Database to Output Directory
Copy-Item -Path "$DatabaseFile" -Destination "$OUTPUT_FOLDER/QuarantineEventsV2.db"

# Get Data
$Query = "SELECT LSQuarantineEventIdentifier,LSQuarantineTimeStamp,LSQuarantineAgentBundleIdentifier,LSQuarantineAgentName,LSQuarantineDataURLString,LSQuarantineSenderName,LSQuarantineSenderAddress,LSQuarantineTypeNumber,LSQuarantineOriginTitle,LSQuarantineOriginURLString,LSQuarantineOriginAlias FROM LSQuarantineEvent;"
$headers = @(
    "EventIdentifier",
    "Timestamp",
    "AgentBundleIdentifier",
    "AgentName",
    "DataURLString",
    "SenderName",
    "SenderAddress",
    "TypeNumber",
    "OriginTitle",
    "OriginURLString",
    "OriginAlias"
)
$raw = & $SQLite3 -separator ',' -readonly "$OUTPUT_FOLDER/QuarantineEventsV2.db" "$Query" 2>&1
if ($raw -and ($raw | Select-String -Pattern '^Error:' -Quiet))
{
    Write-Host "[Error] sqlite3 query failed:" -ForegroundColor Red
    $raw | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    Exit
}
$Data = @($raw | ConvertFrom-Csv -Header $headers)

# Count Records
$Count = ($Data | Measure-Object).Count
Write-Output "[Info]  Processing $Count records ..."

# Processing data
$Results = [Collections.Generic.List[PSObject]]::new()
ForEach($Record in $Data)
{
    # EventIdentifier
    $EventIdentifier = $Record.EventIdentifier

    # Timestamp (Cocoa Core Data Timestamp)
    # 978307200 = January 1, 2001 00:00:00 UTC
    if ($Record.Timestamp)
    {
        $timestampSeconds = 0.0
        if ([double]::TryParse([string]$Record.Timestamp, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$timestampSeconds))
        {
            $CocoaDate = [DateTime]"1/1/2001"
            $TimeZone = [TimeZoneInfo]::FindSystemTimeZoneById('UTC')
            $Timestamp_UTC = [TimeZoneInfo]::ConvertTimeFromUtc($CocoaDate.AddSeconds($timestampSeconds), $TimeZone).ToString("yyyy-MM-dd HH:mm:ss")
        }
        else
        {
            $Timestamp_UTC = ""
        }
    }
    else
    {
        $Timestamp_UTC = ""
    }

    # AgentBundleIdentifier
    $AgentBundleIdentifier = $Record.AgentBundleIdentifier

    # AgentName (Application that downloaded the file)
    $AgentName = $Record.AgentName

    # DataURLString (Download URL)
    $DataURLString = $Record.DataURLString

    # SenderName
    $SenderName = $Record.SenderName

    # SenderAddress
    $SenderAddress = $Record.SenderAddress

    # TypeNumber
    $Type = $Record.TypeNumber
    switch($Type)
    {
        "0" { $TypeNumber = "0 - Web Download" }
        "1" { $TypeNumber = "1 - Email Attachment" }
        "2" { $TypeNumber = "2 - iMessage Attachment" }
        "3" { $TypeNumber = "3 - Calendar Event" }
        "4" { $TypeNumber = "4 - App Store" }
        "5" { $TypeNumber = "5 - AirDrop" }
        "6" { $TypeNumber = "6 - Unknown" }
        "7" { $TypeNumber = "7 - Bluetooth Transfer" }
        default { $TypeNumber = "$Type - Unknown" }
    }

    # OriginTitle (Website Title or Email Subject)
    $OriginTitle = $Record.OriginTitle

    # OriginURLString (Referring URL)
    $OriginURLString = $Record.OriginURLString

    # OriginAlias (Base64 encoded alias data)
    $OriginAlias = $Record.OriginAlias

    $Line = [PSCustomObject]@{
        "Event Identifier"          = $EventIdentifier
        "Timestamp (UTC)"           = $Timestamp_UTC
        "Agent Bundle Identifier"   = $AgentBundleIdentifier
        "Agent Name"                = $AgentName
        "Data URL String"           = $DataURLString
        "Sender Name"               = $SenderName
        "Sender Address"            = $SenderAddress
        "Type Number"               = $TypeNumber
        "Origin Title"              = $OriginTitle
        "Origin URL String"         = $OriginURLString
        "Origin Alias"              = $OriginAlias
    }

    $Results.Add($Line)
}

$Results | Export-Csv -Path "$OUTPUT_FOLDER/CSV/QuarantineEvents.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if ($script:EnableExcel -and (Test-Path "$OUTPUT_FOLDER/CSV/QuarantineEvents.csv"))
{
    if ((Get-Item "$OUTPUT_FOLDER/CSV/QuarantineEvents.csv").Length -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER/CSV/QuarantineEvents.csv" -Delimiter ","
        $Import | Export-Excel -Path "$OUTPUT_FOLDER/XLSX/QuarantineEvents.xlsx" -NoNumberConversion * -FreezePane 2,3 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "QuarantineEvents" -CellStyleSB {
        param($WorkSheet)
        if ($script:UseExcelStyling)
        {
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-B and F-H
            $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["F:H"].Style.HorizontalAlignment="Center"
        }
        }
    }
}

# File Size (XLSX)
if ($script:EnableExcel -and (Test-Path "$OUTPUT_FOLDER/XLSX/QuarantineEvents.xlsx"))
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER/XLSX/QuarantineEvents.xlsx").Length)
    Write-Output "[Info]  File Size (XLSX): $Size"
}

}

#endregion Analysis

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Stats

Function Get-Stats {

# Create Stats directory
New-Item "$OUTPUT_FOLDER/Stats" -ItemType Directory -Force | Out-Null

if (Test-Path "$OUTPUT_FOLDER/CSV/QuarantineEvents.csv")
{
    $Data = Import-Csv "$OUTPUT_FOLDER/CSV/QuarantineEvents.csv" -Delimiter ","
    $Total = ($Data | Measure-Object).Count

    # Agent Name (Stats)
    if ($Total -ge 1)
    {
        $Stats = $Data | Group-Object "Agent Name" | Select-Object @{Name='Agent Name'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
        if ($script:EnableExcel)
        {
            $Stats | Export-Excel -Path "$OUTPUT_FOLDER/Stats/AgentName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AgentName" -CellStyleSB {
            param($WorkSheet)
            if ($script:UseExcelStyling)
            {
                Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
                $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
            }
            }
        }
        else
        {
            $Stats | Export-Csv -Path "$OUTPUT_FOLDER/Stats/AgentName.csv" -NoTypeInformation -Encoding UTF8
        }
    }

    # Type Number (Stats)
    if ($Total -ge 1)
    {
        $Stats = $Data | Group-Object "Type Number" | Select-Object @{Name='Type Number'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
        if ($script:EnableExcel)
        {
            $Stats | Export-Excel -Path "$OUTPUT_FOLDER/Stats/TypeNumber.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "TypeNumber" -CellStyleSB {
            param($WorkSheet)
            if ($script:UseExcelStyling)
            {
                Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
                $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
            }
            }
        }
        else
        {
            $Stats | Export-Csv -Path "$OUTPUT_FOLDER/Stats/TypeNumber.csv" -NoTypeInformation -Encoding UTF8
        }
    }

    # Agent Bundle Identifier (Stats)
    if ($Total -ge 1)
    {
        $Stats = $Data | Group-Object "Agent Bundle Identifier" | Select-Object @{Name='Agent Bundle Identifier'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
        if ($script:EnableExcel)
        {
            $Stats | Export-Excel -Path "$OUTPUT_FOLDER/Stats/AgentBundleIdentifier.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AgentBundleIdentifier" -CellStyleSB {
            param($WorkSheet)
            if ($script:UseExcelStyling)
            {
                Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
                $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
            }
            }
        }
        else
        {
            $Stats | Export-Csv -Path "$OUTPUT_FOLDER/Stats/AgentBundleIdentifier.csv" -NoTypeInformation -Encoding UTF8
        }
    }
}

}

#endregion Stats

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
    $MessageBody = "Status: Quarantine Analysis completed."
    $MessageTitle = "Quarantine-Analyzer.ps1 (https://lethal-forensics.com/)"
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
    Write-Host "================================================" -ForegroundColor Green
    Write-Host "  Quarantine Analysis completed successfully!   " -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
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
Invoke-Quarantine
Get-Stats
Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################
