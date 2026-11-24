# FSEvents-Analyzer v0.1
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
# FSEventsParser v4.1 (2024-12-04)
# https://github.com/dlcowen/FSEventsParser
#
# fsevents_parser_rs v0.1.1 (2024-07-20)
# https://github.com/Houwenda/FSEventsParser-rs
#
# ImportExcel v7.8.10 (2024-10-21)
# https://github.com/dfinke/ImportExcel
#
# Python 3
# https://www.python.org/downloads/
#
# SQLite Tools for Windows v3.50.4 (2025-07-30)
# https://sqlite.org/download.html --> Command-line tools for Windows x64 --> sqlite-tools-win-x64-3500400.zip
#
# xsv v0.13.0 (2018-05-12)
# https://github.com/BurntSushi/xsv
#
#
# Changelog:
# Version 0.1
# Release Date: 2025-11-10
# Initial Release
#
#
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.6456) and PowerShell 5.1 (5.1.19041.6456)
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.6456) and PowerShell 7.5.5
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  FSEvents-Analyzer v0.1 - Automated Forensic Analysis of FSEvent Logs for DFIR

.DESCRIPTION
  FSEvents-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of the macOS File System Event Logs (FsEvents).
  
  FSEvent Logs are written to disk by macOS APIs and contain historical records of file system activity that occurred for a particular volume.

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\FSEvents-Analyzer".

  Note: The subdirectory 'FSEvents-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the input directory.

.EXAMPLE
  PS> .\FSEvents-Analyzer.ps1

.EXAMPLE
  PS> .\FSEvents-Analyzer.ps1 -InputDir "$env:USERPROFILE\Desktop\FSEvents_Data\.fseventsd"

.EXAMPLE
  PS> .\FSEvents-Analyzer.ps1 -InputDir "H:\MacOS-Analyzer-Suite\FSEvents_Data\.fseventsd" -OutputDir "H:\MacOS-Analyzer-Suite"

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
    [String]$InputDir,
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

# Colors / Styling (XLSX only)
Add-Type -AssemblyName System.Drawing
$script:Green  = [System.Drawing.Color]::FromArgb(0,176,80) # Green
$script:Orange = [System.Drawing.Color]::FromArgb(255,192,0) # Orange
$script:UseExcelStyling = [bool]$script:EnableExcel

# Output Directory
if (!($OutputDir))
{
    if ($script:OnMacOS -or $script:OnLinux)
    {
        $script:OUTPUT_FOLDER = Join-Path (Join-Path $HOME "Desktop") "FSEvents-Analyzer"
    }
    else
    {
        $script:OUTPUT_FOLDER = Join-Path (Join-Path $env:USERPROFILE "Desktop") "FSEvents-Analyzer"
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
        $script:OUTPUT_FOLDER = Join-Path $OutputDir "FSEvents-Analyzer"
    }
}

# Tools

# FSEventsParser by David Cowen and Nicole Ibrahim
$script:ReportQueries = "$SCRIPT_DIR\Tools\FSEventsParser\report_queries.json"

# FSEventsParser-rs
$script:FSEventsParser = Join-Path $SCRIPT_DIR "Tools/FSEventsParser-rs/fsevents_parser_rs.exe"

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
    $script:SQLite3 = Join-Path $SCRIPT_DIR "Tools/SQLite/sqlite3.exe"
}

# xsv
if ($script:OnMacOS -or $script:OnLinux)
{
    $script:xsv = (Get-Command xsv -ErrorAction SilentlyContinue).Source
    if (-not $script:xsv)
    {
        # Use compatibility function if xsv is not installed
        $script:xsv = "script:Invoke-XsvCompat"
    }
}
else
{
    $script:xsv = Join-Path $SCRIPT_DIR "Tools/xsv/xsv.exe"
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
        if ($Config.ImportExcel.BackgroundColor -cnotmatch '^(([0-1]?[0-9]?[0-9])|([2][0-4][0-9])|(25[0-5])),(([0-1]?[0-9]?[0-9])|([2][0-4][0-9])|(25[0-5])),(([0-1]?[0-9]?[0-9])|([2][0-4][0-9])|(25[0-5]))$') # <0-255>,<0-255>,<0-255>
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
$Host.UI.RawUI.WindowTitle = "FSEvents-Analyzer v0.1 - Automated Forensic Analysis of FSEvent Logs for DFIR"

# Check if the PowerShell script is being run with elevated privileges
if ($script:OnMacOS -or $script:OnLinux)
{
    $currentUser = & id -u
    if ($currentUser -ne "0")
    {
        Write-Host "[Warning] This script may require elevated privileges (sudo) for some operations." -ForegroundColor Yellow
        # Don't exit - allow the script to continue and fail gracefully if needed
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
            Write-Host "[Info]  XLSX output is disabled by default. CSV/TSV output will be created." -ForegroundColor Yellow
            Write-Host "[Info]  To enable XLSX (optional): install ImportExcel and run with -NoExcel:`$false" -ForegroundColor Yellow
        }
    }
    else
    {
        Write-Host "[Info]  ImportExcel not installed. XLSX output will be skipped." -ForegroundColor Yellow
        Write-Host "[Info]  Install (optional): Install-Module -Name ImportExcel -Scope CurrentUser" -ForegroundColor Yellow
    }
}

# If Excel export is disabled, define no-op stubs so the script can still run (CSV/TSV output remains)
if (-not $script:EnableExcel)
{
    Function Export-Excel {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline = $true)]
            $InputObject,

            [string]$Path,
            [object]$NoNumberConversion,
            [switch]$FreezeTopRow,
            [switch]$BoldTopRow,
            [switch]$AutoSize,
            [switch]$AutoFilter,
            [string]$WorkSheetname,
            [ScriptBlock]$CellStyleSB
        )
        process { return }
    }
}

# Check if sqlite3 exists
if (!(Test-Path "$($SQLite3)"))
{
    Write-Host "[Error] sqlite3 NOT found." -ForegroundColor Red
    Exit
}

# xsv is optional (we fall back to a compatibility function on macOS/Linux)

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

# xsv compatibility function (used if xsv isn't installed)
Function script:Invoke-XsvCompat {
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [object[]]$Args
    )

    # Only supports: xsv count [-d DELIM] <file>
    if (-not $Args -or $Args.Count -lt 2) { return 0 }
    if ($Args[0] -ne "count") { return 0 }

    $delim = ","
    $path = $null

    if ($Args.Count -ge 4 -and $Args[1] -eq "-d")
    {
        $delim = [string]$Args[2]
        $path = [string]$Args[3]
    }
    else
    {
        $path = [string]$Args[1]
    }

    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path $path)) { return 0 }

    try
    {
        $lineCount = 0
        foreach ($line in [System.IO.File]::ReadLines($path))
        {
            $lineCount++
        }
        if ($lineCount -le 1) { return 0 }
        return ($lineCount - 1)
    }
    catch
    {
        return 0
    }
}

# Add the required MessageBox class (Windows PowerShell)
if ($script:OnWindows)
{
    Add-Type -AssemblyName System.Windows.Forms
}

# macOS folder picker (Explorer-like) via osascript
Function script:Select-FolderMacOS {
    param(
        [string]$Prompt = "Choose a folder"
    )
    try
    {
        $escapedPrompt = $Prompt.Replace('"','\"')
        $result = & osascript -e "POSIX path of (choose folder with prompt `"$escapedPrompt`")" 2>$null
        if ([string]::IsNullOrWhiteSpace($result)) { return $null }
        return ($result.Trim())
    }
    catch
    {
        return $null
    }
}

# Select folder containing FSEvent Data
if(!($InputDir))
{
    if ($script:OnWindows)
    {
        Function Get-FolderPath($InitialDirectory)
        {
            [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
            $script:OpenFolderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
            $OpenFolderDialog.Description = 'Select a folder containing FSEvent Data'
            $OpenFolderDialog.ShowNewFolderButton = $false
            $OpenFolderDialog.RootFolder = "MyComputer"
            $Topmost = New-Object System.Windows.Forms.Form
            $Topmost.TopMost = $True
            $Topmost.MinimizeBox = $True
            $OpenFolderDialog.ShowDialog($Topmost)
        }

        $Result = Get-FolderPath
        if($Result -eq "OK")
        {
            $script:FolderPath = $OpenFolderDialog.SelectedPath
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
            $picked = Select-FolderMacOS -Prompt "Select a folder containing FSEvent Data (.fseventsd)"
            if ($picked)
            {
                $script:FolderPath = $picked
            }
            else
            {
                Write-Host ""
                $script:FolderPath = Read-Host "Enter folder path containing FSEvent data"
            }
        }
        else
        {
            $script:FolderPath = Read-Host "Enter folder path containing FSEvent data"
        }
        if ([string]::IsNullOrWhiteSpace($script:FolderPath))
        {
            Write-Host "[Error] No folder path provided." -ForegroundColor Red
            Exit
        }
        # Expand ~ to home directory
        if ($script:FolderPath.StartsWith("~"))
        {
            $script:FolderPath = $script:FolderPath.Replace("~", $HOME)
        }
    }
}
else
{
    $script:FolderPath = $InputDir
    # Expand ~ to home directory
    if ($script:FolderPath.StartsWith("~"))
    {
        $script:FolderPath = $script:FolderPath.Replace("~", $HOME)
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
Write-Output "FSEvents-Analyzer v0.1 - Automated Forensic Analysis of FSEvents Logs for DFIR"
Write-Output "(c) 2026 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Analysis date (ISO 8601)
$AnalysisDate = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "Analysis date: $AnalysisDate UTC"
Write-Output ""

# Input-Check
if (!(Test-Path "$FolderPath"))
{
    Write-Host "[Error] $FolderPath does not exist." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}
else
{
    if (!(Get-Item $FolderPath) -is [System.IO.DirectoryInfo])
    {
        Write-Host "[Error] No Folder Path provided." -ForegroundColor Red
        Write-Host ""
        Stop-Transcript
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }
}

# Count GZIP Archive Files
[int]$GZip = "0"
$Files = (Get-ChildItem $FolderPath -Exclude "fseventsd-uuid").FullName
ForEach ($File in $Files)
{
    if ($PSEdition -eq "Core")
    {
        $Bytes = (Get-Content -Path $File -AsByteStream -ReadCount 1 -TotalCount 2) # PowerShell 7
    }
    else
    {
        $Bytes = (Get-Content -Path $File -Encoding Byte -ReadCount 1 -TotalCount 2) # PowerShell 5.1
    }

    $Signature = ([System.BitConverter]::ToString($Bytes)).Replace("-"," ")
    if ($Signature -eq "1F 8B") # Magic Bytes
    {
        $GZip++
    }
}

Write-Output "[Info]  Processing $GZip FSEvent Log Files ..."

# Input Size
$InputSize = Get-FileSize((Get-ChildItem -Path "$FolderPath" -Exclude "fseventsd-uuid" | Measure-Object Length -Sum).Sum)
Write-Output "[Info]  Total Input Size: $InputSize"

}

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Analysis

# FSEvents

# FSEvents are a critical macOS forensic artifact that logs file system changes, such as creation, deletion, and modification, within the ./fseventsd directory.
# Forensic investigators use FSEvents to reconstruct user activity, track file movements, identify deleted files, and detect unauthorized operations, even in cases where other logs may be cleared. 

# https://github.com/libyal/dtformats/blob/main/documentation/MacOS%20File%20System%20Events%20Disk%20Log%20Stream%20format.asciidoc

Function Invoke-FSEventsParser {

$StartTime_FSEventsParser = (Get-Date)

# FSEventsParser-rs by Houwenda
if ($script:OnWindows -and (Test-Path "$($FSEventsParser)"))
{
    Write-Output "[Info]  Parsing FSEvents Data w/ FSEventsParser-rs ..."
    New-Item "$OUTPUT_FOLDER\FSEventsParser-rs" -ItemType Directory -Force | Out-Null

    # SQLite
    & $FSEventsParser -i "$FolderPath" -o "$OUTPUT_FOLDER\FSEventsParser-rs\FSEventsParser.sqlite" -f sqlite > "$OUTPUT_FOLDER\FSEventsParser-rs\FSEventsParser-rs.txt"

    $SQL = 
    "
    CREATE TABLE 'FSEventsParser'
    (
        'Event ID' TEXT NOT NULL,
        'Full Path' TEXT,
        'Record Flags' TEXT,
        'Creation Time' INTEGER,
        'Last Modified Time' INTEGER,
        'Source' TEXT NOT NULL
    );
    INSERT INTO 'FSEventsParser'
    SELECT
	id AS 'Event ID',
	path as 'Full Path',
	flags AS 'Record Flags',
	DATETIME(create_ts,'UNIXEPOCH') AS 'Creation Time',
	DATETIME(modify_ts,'UNIXEPOCH') AS 'Last Modified',
	source AS Source
    FROM record;
    DROP TABLE 'record';
    VACUUM;
    "

    & $SQLite3 "$OUTPUT_FOLDER\FSEventsParser-rs\FSEventsParser.sqlite" $SQL

    # CSV
    New-Item "$OUTPUT_FOLDER\FSEventsParser-rs\CSV" -ItemType Directory -Force | Out-Null
    $DBPath = "$OUTPUT_FOLDER\FSEventsParser-rs\FSEventsParser.sqlite"
    & $SQLite3 -readonly -csv -header $DBPath "SELECT * FROM FSEventsParser" | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\CSV\FSEventsParser.csv" -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\FSEventsParser-rs\CSV\FSEventsParser.csv")
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\CSV\FSEventsParser.csv" -Delimiter "," -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\XLSX\FSEventsParser.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "FSEvents" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A, C-F
        $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
        }
    }

    # Stats

    # Count Rows of SQLite3 Database (w/ thousands separators)
    [int]$Count = (& $SQLite3 -readonly $DBPath "SELECT COUNT(*) FROM FSEventsParser")
    $Rows = '{0:N0}' -f $Count
    Write-Output "[Info]  Total Records: $Rows"

    # File Size (XLSX)
    if (Test-Path "$OUTPUT_FOLDER\FSEventsParser-rs\XLSX\FSEventsParser.xlsx")
    {
        $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\FSEventsParser-rs\XLSX\FSEventsParser.xlsx").Length)
        Write-Output "[Info]  File Size (XLSX): $Size"
    }

    # Creating Views
    Write-Output "[Info]  Creating Views ..."
    $Files = (Get-ChildItem -Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer" -Filter "*.sql").FullName
    ForEach($File in $Files)
    {
        # Build SQL Query
        $Name = (Get-Item $File).BaseName
        [array]$Prefix = "CREATE VIEW $Name AS" + "`n"
        [array]$Select = Get-Content "$File"
        $Query = $Prefix + $Select
        $Query | & $SQLite3 $DBPath

        # Cleaning up
        $Count = & $SQLite3 $DBPath "SELECT count(*) FROM $Name"
        if ($Count -eq 0)
        {
            & $SQLite3 $DBPath "DROP VIEW $Name"
        }
    }
    
    # Event Reports
    Write-Output "[Info]  Creating Event Reports ..."
    New-Item "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX" -ItemType Directory -Force | Out-Null

    # BashActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\BashActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\BashActivity.sql" | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\BashActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\BashActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\BashActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\BashActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Bash Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # BrowserActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\BrowserActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\BrowserActivity.sql" | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\BrowserActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\BrowserActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\BrowserActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\BrowserActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Browser Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # CloudStorageBoxActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\CloudStorageBoxActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\CloudStorageBoxActivity.sql" | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\CloudStorageBoxActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\CloudStorageBoxActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\CloudStorageBoxActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\CloudStorageBoxActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Box Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # CloudStorageDropBoxActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\CloudStorageDropBoxActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\CloudStorageDropBoxActivity.sql" | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\CloudStorageDropBoxActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\CloudStorageDropBoxActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\CloudStorageDropBoxActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\CloudStorageDropBoxActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DropBox Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # DownloadsActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\DownloadsActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\DownloadsActivity.sql" | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\DownloadsActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\DownloadsActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\DownloadsActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\DownloadsActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Downloads Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # DSStoreActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\DSStoreActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\DSStoreActivity.sql" | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\DSStoreActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\DSStoreActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\DSStoreActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\DSStoreActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname ".DS_Store" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # EmailAttachments
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\EmailAttachments.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\EmailAttachments.sql" | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\EmailAttachments.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\EmailAttachments.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\EmailAttachments.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\EmailAttachments.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Email Attachments" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # FailedPasswordActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\FailedPasswordActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\FailedPasswordActivity.sql" | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\FailedPasswordActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\FailedPasswordActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\FailedPasswordActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\FailedPasswordActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Failed Password Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # GuestAccountActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\GuestAccountActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\GuestAccountActivity.sql" | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\GuestAccountActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\GuestAccountActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\GuestAccountActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\GuestAccountActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Guest Account Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # iCloudSyncronizationActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\iCloudSyncronizationActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\iCloudSyncronizationActivity.sql" | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\iCloudSyncronizationActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\iCloudSyncronizationActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\iCloudSyncronizationActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\iCloudSyncronizationActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "iCloud Syncronization" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # MountActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\MountActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\MountActivity.sql" | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\MountActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\MountActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\MountActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\MountActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Mount Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # OutlookTempActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\OutlookTempActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\OutlookTempActivity.sql" | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\OutlookTempActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\OutlookTempActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\OutlookTempActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\OutlookTempActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Outlook Temp Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # RootShellActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\RootShellActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\RootShellActivity.sql" | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\RootShellActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\RootShellActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\RootShellActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\RootShellActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Root Shell Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # SavedApplicationState
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\SavedApplicationState.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\SavedApplicationState.sql" | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\SavedApplicationState.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\SavedApplicationState.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\SavedApplicationState.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\SavedApplicationState.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Saved Application State" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # SharedFileLists
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\SharedFileLists.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\SharedFileLists.sql" | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\SharedFileLists.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\SharedFileLists.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\SharedFileLists.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\SharedFileLists.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Shared File Lists" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # SudoUsageActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\SudoUsageActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\SudoUsageActivity.sql" | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\SudoUsageActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\SudoUsageActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\SudoUsageActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\SudoUsageActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Sudo Usage Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # TempDirectoryActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\TempDirectoryActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\TempDirectoryActivity.sql" | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\TempDirectoryActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\TempDirectoryActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\TempDirectoryActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\TempDirectoryActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Temp Directory Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # Trash Activity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\TrashActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\TrashActivity.sql" | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\TrashActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\TrashActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\TrashActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\TrashActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Trash Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # UserProfileActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\UserProfileActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\UserProfileActivity.sql" | & $SQLite3 -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UserProfileActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UserProfileActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UserProfileActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\UserProfileActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "User Profile Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # UsersDocumentTypeFiles
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\UsersDocumentTypeFiles.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\UsersDocumentTypeFiles.sql" | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UsersDocumentTypeFiles.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UsersDocumentTypeFiles.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UsersDocumentTypeFiles.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\UsersDocumentTypeFiles.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Users Document Type Files" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # UsersPictureTypeFiles
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\UsersPictureTypeFiles.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\UsersPictureTypeFiles.sql" | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UsersPictureTypeFiles.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UsersPictureTypeFiles.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UsersPictureTypeFiles.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\UsersPictureTypeFiles.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Users Picture Type Files" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # UsersTempDirectoryActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\UsersTempDirectoryActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\UsersTempDirectoryActivity.sql" | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UsersTempDirectoryActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UsersTempDirectoryActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UsersTempDirectoryActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\UsersTempDirectoryActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Users Temp Directory" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # Count Event Reports
    $Total = (Get-ChildItem -Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer" -Filter "*.sql" | Measure-Object).Count
    $Count = (Get-ChildItem -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX" -Filter "*.xlsx" | Measure-Object).Count
    Write-Output "[Info]  $Count Event Reports created ($Total)"
}
else
{
    Write-Host "[Info]  fsevents_parser_rs.exe is Windows-only. Skipping FSEventsParser-rs." -ForegroundColor Yellow
}

$EndTime_FSEventsParser = (Get-Date)
$Time_FSEventsParser = ($EndTime_FSEventsParser-$StartTime_FSEventsParser)
('FSEventsParser duration: {0} h {1} min {2} sec' -f $Time_FSEventsParser.Hours, $Time_FSEventsParser.Minutes, $Time_FSEventsParser.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#############################################################################################################################################################################################

Function Invoke-FSEParser {

$StartTime_FSEParser = (Get-Date)

# FSEventsParser by David Cowen and Nicole Ibrahim
Write-Output "[Info]  Parsing FSEvents Data w/ FSEParser ..."
New-Item "$OUTPUT_FOLDER\FSEParser" -ItemType Directory -Force | Out-Null

# Python 3
if (Test-Path "$SCRIPT_DIR\Tools\FSEventsParser\FSEParser_V4.1.py")
{
    if (Get-Command python -ErrorAction SilentlyContinue)
    {
        python "$SCRIPT_DIR\Tools\FSEventsParser\FSEParser_V4.1.py" -s "$FolderPath" -t folder -o "$OUTPUT_FOLDER\FSEParser" -q "$ReportQueries" > "$OUTPUT_FOLDER\FSEParser\FSEParser.txt"
    }
    else
    {
        Write-Host "[Error] Python 3 NOT found." -ForegroundColor Red
    }
}
else
{
    Write-Host "[Error] FSEParser_V4.1.py NOT found." -ForegroundColor Red
}

# Stats
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSEParser.txt")
{
    $LogFile = Get-Content "$OUTPUT_FOLDER\FSEParser\FSEParser.txt"
    $Attempts = $LogFile | Select-String -Pattern "All Files Attempted:" | ForEach-Object{($_ -split "\s+")[-1]}
    $Parsed = $LogFile | Select-String -Pattern "All Parsed Files:" | ForEach-Object{($_ -split "\s+")[-1]}
    $Errors = $LogFile | Select-String -Pattern "Files with Errors:" | ForEach-Object{($_ -split "\s+")[-1]}
    [int]$Count = $LogFile | Select-String -Pattern "All Records Parsed:" | ForEach-Object{($_ -split "\s+")[-1]}
    $Records = '{0:N0}' -f $Count
    Write-Output "[Info]  All Files Attempted: $Attempts"
    Write-Output "[Info]  All Parsed Files: $Parsed"

    if ($Errors -eq 0)
    {
        Write-Host "[Info]  Files with Errors: 0" -ForegroundColor Green
    }
    else
    {
        Write-Host "[Info]  Files with Errors: $Errors" -ForegroundColor Red
    }

    Write-Output "[Info]  All Records Parsed: $Records"
}

# XLSX
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\All_FSEVENTS.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\All_FSEVENTS.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\All_FSEVENTS.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\All_FSEVENTS.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "All_FSEVENTS" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# File Size (XLSX)
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\All_FSEVENTS.xlsx")
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\All_FSEVENTS.xlsx").Length)
    Write-Output "[Info]  File Size (XLSX): $Size"
}

# Reports

# BashActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\BashActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\BashActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\BashActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\BashActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Bash Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# BrowserActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\BrowserActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\BrowserActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\BrowserActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\BrowserActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Browser Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# CloudStorageBoxActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\CloudStorageBoxActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\CloudStorageBoxActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\CloudStorageBoxActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\CloudStorageBoxActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Box Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# CloudStorageDropBoxActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\CloudStorageDropBoxActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\CloudStorageDropBoxActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\CloudStorageDropBoxActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\CloudStorageDropBoxActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DropBox Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# DownloadsActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\DownloadsActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\DownloadsActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\DownloadsActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\DownloadsActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Downloads Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# DSStoreActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\DSStoreActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\DSStoreActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\DSStoreActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\DSStoreActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname ".DS_Store Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# EmailAttachments.tsv (Apple Mail)
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\EmailAttachments.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\EmailAttachments.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\EmailAttachments.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\EmailAttachments.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Email Attachments" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# FailedPasswordActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\FailedPasswordActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\FailedPasswordActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\FailedPasswordActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\FailedPasswordActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Failed Password Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# GuestAccountActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\GuestAccountActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\GuestAccountActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\GuestAccountActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\GuestAccountActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Guest Account Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# iCloudSyncronizationActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\iCloudSyncronizationActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\iCloudSyncronizationActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\iCloudSyncronizationActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\iCloudSyncronizationActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "iCloud Syncronization" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# MountActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\MountActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\MountActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\MountActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\MountActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Mount Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# RootShellActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\RootShellActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\RootShellActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\RootShellActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\RootShellActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Root Shell Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# SavedApplicationState.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\SavedApplicationState.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\SavedApplicationState.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\SavedApplicationState.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\SavedApplicationState.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Saved Application State" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# SharedFileLists.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\SharedFileLists.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\SharedFileLists.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\SharedFileLists.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\SharedFileLists.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Shared File Lists" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# SudoUsageActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\SudoUsageActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\SudoUsageActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\SudoUsageActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\SudoUsageActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Sudo Usage Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# TrashActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\TrashActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\TrashActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\TrashActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\TrashActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Trash Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# UserProfileActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\UserProfileActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\UserProfileActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\UserProfileActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\UserProfileActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "User Profile Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# UsersDocumentTypeFiles.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\UsersDocumentTypeFiles.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\UsersDocumentTypeFiles.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\UsersDocumentTypeFiles.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\UsersDocumentTypeFiles.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Users Document Type Files" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# UsersPictureTypeFiles.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\UsersPictureTypeFiles.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\UsersPictureTypeFiles.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\UsersPictureTypeFiles.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\UsersPictureTypeFiles.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Users Picture Type Files" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# Count Event Reports
if (Test-Path "$ReportQueries")
{
    $Total = (Get-Content "$ReportQueries" | ConvertFrom-Json | Select-Object -ExpandProperty process_list | Measure-Object).Count
    $Count = (Get-ChildItem -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX" -Exclude "All_FSEVENTS.xlsx" | Measure-Object).Count
    Write-Output "[Info]  $Count Event Reports created ($Total)"
}

$EndTime_FSEParser = (Get-Date)
$Time_FSEParser = ($EndTime_FSEParser-$StartTime_FSEParser)
('FSEParser duration:      {0} h {1} min {2} sec' -f $Time_FSEParser.Hours, $Time_FSEParser.Minutes, $Time_FSEParser.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#endregion Analysis

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

# Completion message
if ($script:OnWindows)
{
    Add-Type -AssemblyName System.Windows.Forms
    $MessageBody = "Status: FSEvents Analysis completed."
    $MessageTitle = "FSEvents-Analyzer.ps1 (https://lethal-forensics.com/)"
    $ButtonType = "OK"
    $MessageIcon = "Information"
    [void][System.Windows.Forms.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon)
}
else
{
    Write-Output "[Info]  FSEvents analysis completed."
}

# Reset Progress Preference
$Global:ProgressPreference = $OriginalProgressPreference

# Reset Windows Title
$Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
Exit

}

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# Main
Header
if ($script:OnWindows -and (Test-Path "$($script:FSEventsParser)"))
{
    Invoke-FSEventsParser
}
Invoke-FSEParser
Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################
