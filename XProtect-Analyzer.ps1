# XProtect-Analyzer v0.2
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
# SQLite Tools
# Windows: https://sqlite.org/download.html
# macOS: Built-in (sqlite3)
#
#
# Changelog:
# Version 0.1
# Release Date: 2025-11-10
# Initial Release
#
# Version 0.2
# Release Date: 2025-11-27
# Added: VirusTotal Lookup
#
# Fork (scott-paterson/MacOS-Analyzer-Suite)
# Added: Native macOS support
#
#
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.6456) and PowerShell 5.1 (5.1.19041.6456)
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.6456) and PowerShell 7.5.5
# Tested on macOS with PowerShell 7.7
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  XProtect-Analyzer v0.2 - Automated Forensic Analysis of macOS XProtect Behavioral Service database for DFIR

.DESCRIPTION
  XProtect-Analyzer.ps1 is a PowerShell script utilized to simplify the processing of the XProtect Behavioral Service (XBS) database for DFIR.

.PARAMETER OutputDir
  Specifies the output directory. Default is "$HOME/Desktop/XProtect-Analyzer" (macOS) or "$env:USERPROFILE\Desktop\XProtect-Analyzer" (Windows).

  Note: The subdirectory 'XProtect-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the input file (XPdb).

.PARAMETER skipVT
  Do not query VirusTotal with item hashes.

.EXAMPLE
  PS> ./XProtect-Analyzer.ps1

.EXAMPLE
  PS> ./XProtect-Analyzer.ps1 -Path "$HOME/Desktop/XPdb"

.EXAMPLE
  PS> ./XProtect-Analyzer.ps1 -Path "$HOME/Desktop/XPdb" -OutputDir "$HOME/Desktop/MacOS-Analyzer-Suite" -skipVT

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
    [switch]$NoExcel = $true,
    [Switch]$skipVT
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
        $script:OUTPUT_FOLDER = "$HOME/Desktop/XProtect-Analyzer"
    }
    else
    {
        $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\XProtect-Analyzer"
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
        $script:OUTPUT_FOLDER = Join-Path $OutputDir "XProtect-Analyzer"
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
$Host.UI.RawUI.WindowTitle = "XProtect-Analyzer v0.2 - Automated Forensic Analysis of macOS XProtect Behavioral Service database for DFIR"

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

# Select XProtect Database
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
            $OpenFileDialog.Filter = "XProtect Database|XPdb;XProtect.db|All Files (*.*)|*.*"
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
            $picked = Select-FileMacOS -Prompt "Select XProtect database (XPdb / XProtect.db)"
            if ($picked)
            {
                $script:DatabaseFile = $picked
            }
            else
            {
                Write-Host ""
                Write-Host "[Info]  Please provide the path to the XProtect database file." -ForegroundColor Cyan
                Write-Host "[Info]  Common location:" -ForegroundColor Cyan
                Write-Host "        - /private/var/protected/xprotect/XPdb" -ForegroundColor Gray
                Write-Host ""
                $script:DatabaseFile = Read-Host "Enter path to database"
            }
        }
        else
        {
            # Linux - Prompt for path
            Write-Host ""
            Write-Host "[Info]  Please provide the path to the XProtect database file." -ForegroundColor Cyan
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
Write-Output "XProtect-Analyzer v0.2 - Automated Forensic Analysis of macOS XProtect Behavioral Service database for DFIR"
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

# XProtect Behavior Service (XBS) Database
# Location: /private/var/protected/xprotect/db/XPdb (macOS 13+)

Function Invoke-XProtect {

# Input-Check
if (!(Test-Path "$DatabaseFile" -PathType Leaf))
{
    Write-Host "[Error] $DatabaseFile does not exist." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check Signature (Magic Number)
if ($PSEdition -eq "Core")
{
    $Bytes = (Get-Content -Path $DatabaseFile -AsByteStream -ReadCount 1 -TotalCount 16) # PowerShell 7
}
else
{
    $Bytes = (Get-Content -Path $DatabaseFile -Encoding Byte -ReadCount 1 -TotalCount 16) # PowerShell 5.1
}

$Signature = ([System.BitConverter]::ToString($Bytes)).Replace("-"," ") # SQLite format 3

if (!($Signature -eq "53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33 00")) # Magic Bytes
{
    Write-Host "[Error] No SQLite3 Database File provided." -ForegroundColor Red
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

$FileName = [IO.Path]::GetFileName($DatabaseFile)
Write-Output "[Info]  Processing XProtect Behavioral Service Database ($FileName) ..."
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

# Input Size
$InputSize = Get-FileSize((Get-Item "$DatabaseFile").Length)
Write-Output "[Info]  Total Input Size: $InputSize"

# Work on a copy (incl. WAL/SHM, which can hold events not yet checkpointed into the main file)
$script:WorkingDB = "$OUTPUT_FOLDER/XPdb"
Copy-Item -LiteralPath "$DatabaseFile" -Destination "$WorkingDB"
foreach ($Suffix in @("-wal","-shm"))
{
    if (Test-Path -LiteralPath "$DatabaseFile$Suffix" -PathType Leaf)
    {
        Copy-Item -LiteralPath "$DatabaseFile$Suffix" -Destination "$WorkingDB$Suffix"
    }
}

# Count Rows of SQLite3 Database (w/ thousands separators)
$CountOutput = & $SQLite3 -readonly "$WorkingDB" 'SELECT COUNT(*) FROM EVENTS' 2>&1
if ($LASTEXITCODE -ne 0)
{
    Write-Host "[Error] sqlite3 query failed: $CountOutput" -ForegroundColor Red
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}
[int]$Count = $CountOutput
$Rows = '{0:N0}' -f $Count
Write-Output "[Info]  Total Lines: $Rows"

# EVENTS Table (Untouched)
& $SQLite3 -readonly -csv -header "$WorkingDB" 'SELECT * FROM EVENTS' | Out-File "$OUTPUT_FOLDER/CSV/Untouched.csv" -Encoding UTF8

if ($script:EnableExcel -and (Test-Path "$OUTPUT_FOLDER/CSV/Untouched.csv") -and $Count -ge 1)
{
    $IMPORT = Import-Csv "$OUTPUT_FOLDER/CSV/Untouched.csv" -Delimiter ","
    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER/XLSX/Untouched.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Events" -CellStyleSB {
    param($WorkSheet)
    if ($script:UseExcelStyling)
    {
        $ColumnNumber = $WorkSheet.Dimension.End.Column
        $ColumnName = (Get-ExcelColumnName $ColumnNumber).ColumnName
        Set-Format -Address $WorkSheet.Cells["A1:$($ColumnName)1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        $WorkSheet.Cells["A:$($ColumnName)"].Style.HorizontalAlignment="Center"
    }
    }
}

# SQL Query
$SQL = @"
SELECT
    dt AS 'DateTime',
    violated_rule AS 'Bastion Rule',
    exec_path AS 'Path',
    exec_signing_id AS 'Identifier',
    exec_team_id AS 'Team Identifier',
    exec_sha256 AS 'SHA256',
    CASE exec_is_notarized
        WHEN 0 THEN 'No'
        WHEN 1 THEN 'Yes'
    END AS 'Notarized',
    CASE reported
        WHEN 0 THEN 'No'
        WHEN 1 THEN 'Yes'
    END AS 'Reported'
FROM EVENTS
"@

$Results = @(& $SQLite3 -readonly -csv -header "$WorkingDB" "$SQL" | ConvertFrom-Csv)

$Output = [Collections.Generic.List[PSObject]]::new()
ForEach($Record in $Results)
{
    $DateTime = ""
    if ($Record.DateTime)
    {
        $Parsed = [datetime]::MinValue
        if ([datetime]::TryParse($Record.DateTime, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$Parsed))
        {
            $DateTime = $Parsed.ToString("yyyy-MM-dd HH:mm:ss")
        }
        else
        {
            $DateTime = $Record.DateTime
        }
    }

    $Line = [PSCustomObject]@{
    "DateTime"        = $DateTime
    "Bastion Rule"    = $Record."Bastion Rule"
    "Path"            = $Record.Path
    "Identifier"      = $Record.Identifier
    "Team Identifier" = $Record."Team Identifier"
    "SHA256"          = $Record.SHA256
    "Notarized"       = $Record.Notarized
    "Reported"        = $Record.Reported
    }

    $Output.Add($Line)
}

$Output | Export-Csv -Path "$OUTPUT_FOLDER/CSV/XProtect-BehaviorService.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if ($script:EnableExcel -and $Output.Count -ge 1)
{
    $IMPORT = Import-Csv "$OUTPUT_FOLDER/CSV/XProtect-BehaviorService.csv" -Delimiter "," -Encoding UTF8 | Sort-Object { $_.DateTime -as [datetime] } -Descending
    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER/XLSX/XProtect-BehaviorService.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "XBS" -CellStyleSB {
    param($WorkSheet)
    if ($script:UseExcelStyling)
    {
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:H1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B and D-H
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["D:H"].Style.HorizontalAlignment="Center"
        # ConditionalFormatting - Notarized
        $LastRow = $WorkSheet.Dimension.End.Row
        Add-ConditionalFormatting -Address $WorkSheet.Cells["G2:G$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Yes",$G2)))' -BackgroundColor $Green
        Add-ConditionalFormatting -Address $WorkSheet.Cells["G2:G$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("No",$G2)))' -BackgroundColor Red
    }
    }
}

# File Size (XLSX)
if ($script:EnableExcel -and (Test-Path "$OUTPUT_FOLDER/XLSX/XProtect-BehaviorService.xlsx"))
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER/XLSX/XProtect-BehaviorService.xlsx").Length)
    Write-Output "[Info]  File Size (XLSX): $Size"
}

}

#endregion Analysis

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Stats

Function script:Export-Stats {
    Param($Stats, [string]$Name, [string]$WorkSheetName, [string]$CenterColumns)

    if ($script:EnableExcel)
    {
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER/Stats/$Name.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "$WorkSheetName" -CellStyleSB {
        param($WorkSheet)
        if ($script:UseExcelStyling)
        {
            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            $WorkSheet.Cells[$CenterColumns].Style.HorizontalAlignment="Center"
        }
        }
    }
    else
    {
        $Stats | Export-Csv -Path "$OUTPUT_FOLDER/Stats/$Name.csv" -NoTypeInformation -Encoding UTF8
    }
}

Function Get-Stats {

New-Item "$OUTPUT_FOLDER/Stats" -ItemType Directory -Force | Out-Null

if (!(Test-Path "$OUTPUT_FOLDER/CSV/XProtect-BehaviorService.csv")) { return }

$XBS = @(Import-Csv "$OUTPUT_FOLDER/CSV/XProtect-BehaviorService.csv" -Delimiter "," -Encoding UTF8 | Sort-Object { $_.DateTime -as [datetime] })
if ($XBS.Count -lt 1) { return }

# Time Frame
$StartDateTime = $XBS[0].DateTime
$EndDateTime = $XBS[-1].DateTime
Write-Output "[Info]  Log data from $StartDateTime UTC until $EndDateTime UTC"

# Bastion Rules
$Total = $XBS.Count
$Count = ($XBS | Select-Object "Bastion Rule" -Unique | Measure-Object).Count
Write-Output "[Info]  $Count violated Bastion Rules found ($Total)"

# Signing Identifier
$Count = ($XBS | Select-Object "Identifier" -Unique | Measure-Object).Count
Write-Output "[Info]  $Count Signing Identifier found ($Total)"

# Team Identifier
$Count = ($XBS | Select-Object "Team Identifier" -Unique | Measure-Object).Count
Write-Output "[Info]  $Count Team Identifier found ($Total)"

# SHA256
New-Item "$OUTPUT_FOLDER/TXT" -ItemType Directory -Force | Out-Null
$SHA256 = @($XBS | Where-Object { $_.SHA256 -match "^[A-Fa-f0-9]{64}$" } | Select-Object SHA256 -Unique | Sort-Object SHA256).SHA256
$SHA256 | Out-File "$OUTPUT_FOLDER/TXT/SHA256.txt" -Encoding UTF8
Write-Output "[Info]  $($SHA256.Count) SHA256 Hash Value(s) found"

# Bastion Rule (Stats)
$Stats = $XBS | Group-Object "Bastion Rule" | Select-Object @{Name='Bastion Rule'; Expression={ $_.Values[0] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
Export-Stats -Stats $Stats -Name "Bastion-Rules" -WorkSheetName "Bastion Rules" -CenterColumns "B:C"

# Identifier (Stats)
$Subset = @($XBS | Where-Object { $_.Identifier -ne "" })
if ($Subset.Count -ge 1)
{
    $Stats = $Subset | Group-Object Identifier | Select-Object @{Name='Identifier'; Expression={ $_.Values[0] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Subset.Count)}} | Sort-Object Count -Descending
    Export-Stats -Stats $Stats -Name "Identifier" -WorkSheetName "Identifier" -CenterColumns "B:C"
}

# Notarized (Stats)
$Subset = @($XBS | Where-Object { $_.Notarized -ne "" })
if ($Subset.Count -ge 1)
{
    $Stats = $Subset | Group-Object Notarized | Select-Object @{Name='Notarized'; Expression={ $_.Values[0] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Subset.Count)}} | Sort-Object Count -Descending
    Export-Stats -Stats $Stats -Name "Notarized" -WorkSheetName "Notarized" -CenterColumns "A:C"
}

# Reported (Stats)
$Subset = @($XBS | Where-Object { $_.Reported -ne "" })
if ($Subset.Count -ge 1)
{
    $Stats = $Subset | Group-Object Reported | Select-Object @{Name='Reported'; Expression={ $_.Values[0] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Subset.Count)}} | Sort-Object Count -Descending
    Export-Stats -Stats $Stats -Name "Reported" -WorkSheetName "Reported" -CenterColumns "A:C"
}

# Team Identifier (Stats)
$Stats = $XBS | Group-Object "Team Identifier" | Select-Object @{Name='Team Identifier'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
Export-Stats -Stats $Stats -Name "Team-Identifier" -WorkSheetName "Team Identifier" -CenterColumns "B:C"

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
    $MessageBody = "Status: XProtect Analysis completed."
    $MessageTitle = "XProtect-Analyzer.ps1 (https://lethal-forensics.com/)"
    $ButtonType = "OK"
    $MessageIcon = "Information"
    [System.Windows.Forms.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon) | Out-Null

    $Global:ProgressPreference = $OriginalProgressPreference
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
}
else
{
    # macOS/Linux - Console message
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host "  XProtect Analysis completed successfully!    " -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Output directory: $OUTPUT_FOLDER" -ForegroundColor Cyan
    Write-Host ""
    
    $Global:ProgressPreference = $OriginalProgressPreference
}

}

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region VirusTotal

Function Invoke-VirusTotal {

if ($skipVT.IsPresent) { return }

$HashList = Join-Path (Join-Path $OUTPUT_FOLDER "TXT") "SHA256.txt"
if (!(Test-Path $HashList) -or (Get-Item $HashList).Length -eq 0) { return }

$VTScript = Join-Path $PSScriptRoot "VirusTotal-Analyzer.ps1"
if (!(Test-Path $VTScript)) { return }

$Title   = "VirusTotal-Analyzer"
$Prompt  = "Do you want to check the item hashes on VirusTotal?"
$Choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No")
$Choice  = $host.UI.PromptForChoice($Title, $Prompt, $Choices, 0)

if ($Choice -eq 0)
{
    $VTOutput = Join-Path $OUTPUT_FOLDER "VirusTotal"
    New-Item $VTOutput -ItemType Directory -Force | Out-Null
    & $VTScript -Path $HashList -OutputDir $VTOutput
}

}

#endregion VirusTotal

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# Main
Header
Invoke-XProtect
Get-Stats
Footer
Invoke-VirusTotal

#############################################################################################################################################################################################
#############################################################################################################################################################################################
