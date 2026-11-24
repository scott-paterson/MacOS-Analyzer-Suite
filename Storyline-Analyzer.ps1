# Storyline-Analyzer v0.2
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
# xsv v0.13.0 (2018-05-12)
# https://github.com/BurntSushi/xsv
# macOS: brew install xsv
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
  Storyline-Analyzer v0.2 - Automated Forensic Analysis of Aftermath Storyline

.DESCRIPTION
  Storyline-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of the Aftermath Storyline (storyline.csv) to potentially track down the infection vector.

  https://github.com/jamf/aftermath

.PARAMETER OutputDir
  Specifies the output directory. Default is "$HOME/Desktop/Storyline-Analyzer" (macOS) or "$env:USERPROFILE\Desktop\Storyline-Analyzer" (Windows).

  Note: The subdirectory 'Storyline-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the input file (storyline.csv).

.EXAMPLE
  PS> ./Storyline-Analyzer.ps1

.EXAMPLE
  PS> ./Storyline-Analyzer.ps1 -Path "$HOME/Desktop/storyline.csv"

.EXAMPLE
  PS> ./Storyline-Analyzer.ps1 -Path "/path/to/storyline.csv" -OutputDir "/path/to/output"

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
        $script:OUTPUT_FOLDER = "$HOME/Desktop/Storyline-Analyzer"
    }
    else
    {
        $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\Storyline-Analyzer"
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
        $script:OUTPUT_FOLDER = Join-Path $OutputDir "Storyline-Analyzer"
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

# xsv
if ($script:OnMacOS -or $script:OnLinux)
{
    # Check for xsv in PATH (installed via Homebrew)
    $script:xsv = (Get-Command xsv -ErrorAction SilentlyContinue).Source
    if (-not $script:xsv)
    {
        $script:xsv = "/opt/homebrew/bin/xsv"
        if (-not (Test-Path $script:xsv))
        {
            $script:xsv = "/usr/local/bin/xsv"
        }
    }
}
else
{
    $script:xsv = "$SCRIPT_DIR\Tools\xsv\xsv.exe"
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
$Host.UI.RawUI.WindowTitle = "Storyline-Analyzer v0.2 - Automated Forensic Analysis of Aftermath Storyline"

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

# Check if xsv exists
if (!(Test-Path "$($xsv)"))
{
    Write-Host "[Error] xsv NOT found." -ForegroundColor Red
    if ($script:OnMacOS)
    {
        Write-Host "[Info]  Install with: brew install xsv" -ForegroundColor Yellow
    }
    elseif ($script:OnLinux)
    {
        Write-Host "[Info]  Install from: https://github.com/BurntSushi/xsv" -ForegroundColor Yellow
    }
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

# Select Aftermath Storyline File (storyline.csv)
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
            $OpenFileDialog.Filter = "Storyline|storyline.csv|All Files (*.*)|*.*"
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
        if ($script:OnMacOS)
        {
            $picked = Select-FileMacOS -Prompt "Select Aftermath storyline.csv"
            if ($picked)
            {
                $script:LogFile = $picked
            }
            else
            {
                # Fallback to prompt
                Write-Host ""
                Write-Host "[Info]  Please provide the path to the Aftermath storyline.csv." -ForegroundColor Cyan
                Write-Host ""
                $script:LogFile = Read-Host "Enter path to storyline.csv"
            }
        }
        else
        {
            # Linux - Prompt for path
            Write-Host ""
            Write-Host "[Info]  Please provide the path to the Aftermath storyline.csv." -ForegroundColor Cyan
            Write-Host ""
            $script:LogFile = Read-Host "Enter path to storyline.csv"
        }
        
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
Write-Output "Storyline-Analyzer v0.2 - Automated Forensic Analysis of Aftermath Storyline for DFIR"
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

# Aftermath Storyline

Function Invoke-Processing {

$StartTime_Processing = (Get-Date)

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
if (!($Extension -eq ".csv" ))
{
    Write-Host "[Error] No CSV File provided." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

$FileName = [IO.Path]::GetFileName($LogFile)
Write-Output "[Info]  Processing Aftermath Storyline ($FileName) ..."
New-Item "$OUTPUT_FOLDER/CSV" -ItemType Directory -Force | Out-Null

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

# Count rows of CSV (w/ thousands separators)
[int]$TotalLines = 0
$Reader = New-Object IO.StreamReader "$LogFile"
while($Reader.ReadLine() -ne $null){ $TotalLines++ }
($Reader.Dispose())
$Rows = '{0:N0}' -f $TotalLines | ForEach-Object {$_ -replace ' ','.'}
Write-Output "[Info]  Total Lines: $Rows" # Duplicates

# Create SQLite Database
Write-Output "[Info]  Initializing SQLite Database. Please wait ..."
New-Item "$OUTPUT_FOLDER/SQLite" -ItemType Directory -Force | Out-Null

$script:DBPath = "$OUTPUT_FOLDER/SQLite/Storyline.db"

$Table = 
"
CREATE TABLE Aftermath (
    Timestamp TEXT,
    Type TEXT,
    Path TEXT,
    Other TEXT
);
"

$SQL = 
"
CREATE TABLE Storyline (
    Timestamp TEXT,
    Type TEXT,
    Path TEXT,
    Other TEXT
);
INSERT INTO Storyline
SELECT
    strftime('%Y-%m-%d %H:%M:%S',Timestamp) AS Timestamp,
    Type,
    Path,
    Other
FROM Aftermath
ORDER BY Timestamp DESC;
DROP TABLE Aftermath;
VACUUM;
"

# Import Aftermath Storyline
$importLog = "$OUTPUT_FOLDER/SQLite/sqlite-import.log"
$importOut = & $SQLite3 "$DBPath" "$Table" ".mode csv" ".import `"$LogFile`" Aftermath" ".exit" 2>&1
if ($importOut)
{
    $importOut | Out-File -FilePath $importLog -Encoding UTF8
    if ($importOut | Select-String -Pattern 'expected 4 columns' -Quiet)
    {
        Write-Host "[Warning] sqlite3 import: some rows had fewer columns; missing values were filled with NULL." -ForegroundColor Yellow
        Write-Host "[Warning] See: $importLog" -ForegroundColor Yellow
    }
    elseif ($importOut | Select-String -Pattern 'error' -Quiet)
    {
        Write-Host "[Warning] sqlite3 import output detected. See: $importLog" -ForegroundColor Yellow
    }
}

# Create SQLite Database
& $SQLite3 $DBPath $SQL

# CSV
& $SQLite3 -readonly -csv -header $DBPath "SELECT * FROM Storyline" | Out-File "$OUTPUT_FOLDER/CSV/Storyline.csv" -Encoding UTF8

# Get End Time
$EndTime_Processing = (Get-Date)

# Duration Processing
$Time_Processing = ($EndTime_Processing-$StartTime_Processing)
('Duration CSV Creation:     {0} h {1} min {2} sec' -f $Time_Processing.Hours, $Time_Processing.Minutes, $Time_Processing.Seconds) >> "$OUTPUT_FOLDER/Stats.txt"

# Count Rows of SQLite3 Database (w/ thousands separators)
[int]$Count = (& $SQLite3 -readonly $DBPath "SELECT COUNT(*) FROM Storyline")
$Rows = '{0:N0}' -f $Count
Write-Output "[Info]  Total Rows: $Rows" # Unique Records

# Time Frame (ISO 8601)
$Start = & $SQLite3 -readonly $DBPath "SELECT Timestamp FROM Storyline WHERE Timestamp NOT LIKE '21%' ORDER BY Timestamp DESC LIMIT 1"
$End = & $SQLite3 -readonly $DBPath "SELECT Timestamp FROM Storyline WHERE Timestamp NOT LIKE '%1970-01-01 00:00:00%' ORDER BY Timestamp ASC LIMIT 1"
Write-Output "[Info]  Log data from $Start UTC until $End UTC"

}

#############################################################################################################################################################################################

Function Get-DatabaseViews {

# Get Start Time
$StartTime_Views = (Get-Date)

# Creating Views
Write-Output "[Info]  Creating Views ..."
$Files = (Get-ChildItem -Path "$SCRIPT_DIR/Queries/Storyline-Analyzer" -Filter "*.sql").FullName
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

# Get End Time
$EndTime_Views = (Get-Date)

# Duration Views
$Time_Views = ($EndTime_Views-$StartTime_Views)
('Duration Views Creation:   {0} h {1} min {2} sec' -f $Time_Views.Hours, $Time_Views.Minutes, $Time_Views.Seconds) >> "$OUTPUT_FOLDER/Stats.txt"

}

#############################################################################################################################################################################################

Function Get-Reports {

# Get Start Time
$StartTime_Reports = (Get-Date)

# Event Reports
Write-Output "[Info]  Creating Event Reports ..."
New-Item "$OUTPUT_FOLDER/Reports/CSV" -ItemType Directory -Force | Out-Null
if ($script:EnableExcel)
{
    New-Item "$OUTPUT_FOLDER/Reports/XLSX" -ItemType Directory -Force | Out-Null
}

# List of reports to generate
$ReportList = @(
    @{Name="BashActivity"; Sheet="Bash Activity"},
    @{Name="BrowserActivity"; Sheet="Browser Activity"},
    @{Name="CloudStorageBoxActivity"; Sheet="Box Activity"},
    @{Name="CloudStorageDropBoxActivity"; Sheet="DropBox Activity"},
    @{Name="DownloadsActivity"; Sheet="Downloads Activity"},
    @{Name="DSStoreActivity"; Sheet=".DS_Store"},
    @{Name="EmailAttachments"; Sheet="Email Attachments"},
    @{Name="FailedPasswordActivity"; Sheet="Failed Password Activity"},
    @{Name="GuestAccountActivity"; Sheet="Guest Account Activity"},
    @{Name="iCloudSyncronizationActivity"; Sheet="iCloud Syncronization"},
    @{Name="MountActivity"; Sheet="Mount Activity"},
    @{Name="OutlookTempActivity"; Sheet="Outlook Temp Activity"},
    @{Name="RootShellActivity"; Sheet="Root Shell Activity"},
    @{Name="SavedApplicationState"; Sheet="Saved Application State"},
    @{Name="SharedFileLists"; Sheet="Shared File Lists"},
    @{Name="SudoUsageActivity"; Sheet="Sudo Usage Activity"},
    @{Name="TempDirectoryActivity"; Sheet="Temp Directory Activity"},
    @{Name="TrashActivity"; Sheet="Trash Activity"},
    @{Name="UserProfileActivity"; Sheet="User Profile Activity"},
    @{Name="UsersDocumentTypeFiles"; Sheet="Users Document Type Files"},
    @{Name="UsersPictureTypeFiles"; Sheet="Users Picture Type Files"},
    @{Name="UsersTempDirectoryActivity"; Sheet="Users Temp Directory"}
)

ForEach ($Report in $ReportList)
{
    $SqlPath = "$SCRIPT_DIR/Queries/Storyline-Analyzer/$($Report.Name).sql"
    if (Test-Path $SqlPath)
    {
        Get-Content $SqlPath | & $SQLite3 -readonly -csv -header $DBPath | Out-File "$OUTPUT_FOLDER/Reports/CSV/$($Report.Name).csv" -Encoding UTF8
        
        if($script:EnableExcel -and ([int](& $xsv count "$OUTPUT_FOLDER/Reports/CSV/$($Report.Name).csv") -gt 0))
        {
            $Import = Import-Csv "$OUTPUT_FOLDER/Reports/CSV/$($Report.Name).csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER/Reports/XLSX/$($Report.Name).xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname $Report.Sheet -CellStyleSB {
            param($WorkSheet)
            if ($script:UseExcelStyling)
            {
                # BackgroundColor and FontColor for specific cells of TopRow
                Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
                # HorizontalAlignment "Center" of columns A-B
                $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
            }
            }
        }
    }
}

# Count Event Reports
$Total = (Get-ChildItem -Path "$SCRIPT_DIR/Queries/Storyline-Analyzer" -Filter "*.sql" | Measure-Object).Count
if ($script:EnableExcel -and (Test-Path "$OUTPUT_FOLDER/Reports/XLSX"))
{
    $Count = (Get-ChildItem -Path "$OUTPUT_FOLDER/Reports/XLSX" -Filter "*.xlsx" | Measure-Object).Count
    Write-Output "[Info]  $Count Event Reports created ($Total)"
}
else
{
    Write-Output "[Info]  Event reports exported as CSV only ($Total)"
}

# Get End Time
$EndTime_Reports = (Get-Date)

# Duration Reports
$Time_Reports = ($EndTime_Reports-$StartTime_Reports)
('Duration Reports Creation: {0} h {1} min {2} sec' -f $Time_Reports.Hours, $Time_Reports.Minutes, $Time_Reports.Seconds) >> "$OUTPUT_FOLDER/Stats.txt"

}

#############################################################################################################################################################################################

Function Invoke-Excel {

# Skip Excel export if disabled
if (-not $script:EnableExcel)
{
    return
}

# Get Start Time
$StartTime_XLSX = (Get-Date)

# XLSX
if([int](& $xsv count "$OUTPUT_FOLDER/CSV/Storyline.csv") -gt 0)
{
    [int]$Count = & $xsv count "$OUTPUT_FOLDER/CSV/Storyline.csv"

    if ($Count -gt "1048576")
    {
        Write-Output "[Info]  ImportExcel: Storyline.csv will be splitted [time-consuming task] ..."
        New-Item "$OUTPUT_FOLDER/XLSX" -ItemType Directory -Force | Out-Null
        & $xsv split -s 1000000 "$OUTPUT_FOLDER/CSV" --filename "Storyline-{}.csv" --delimiter "," "$OUTPUT_FOLDER/CSV/Storyline.csv"

        [array]$Files = (Get-ChildItem -Path "$OUTPUT_FOLDER/CSV" | Where-Object {$_.Name -match "Storyline-[0-9].*\.csv"}).FullName

        ForEach( $File in $Files )
        {
            $FileName = Split-Path $File -Leaf
            $FileBaseName = [IO.Path]::GetFileNameWithoutExtension($FileName)
            $Import = Import-Csv "$File" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER/XLSX/$FileBaseName.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Storyline" -CellStyleSB {
            param($WorkSheet)
            if ($script:UseExcelStyling)
            {
                # BackgroundColor and FontColor for specific cells of TopRow
                Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
                # HorizontalAlignment "Center" of columns A-B
                $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
            }
            }
        }
    }
    else
    {
        New-Item "$OUTPUT_FOLDER/XLSX" -ItemType Directory -Force | Out-Null
        $Import = Import-Csv "$OUTPUT_FOLDER/CSV/Storyline.csv" -Delimiter "," -Encoding UTF8 | Sort-Object { $_."Timestamp" -as [datetime] } -Descending
        $Import | Export-Excel -Path "$OUTPUT_FOLDER/XLSX/Storyline.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Storyline" -CellStyleSB {
        param($WorkSheet)
        if ($script:UseExcelStyling)
        {
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-B
            $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
        }
    }
}

# File Size (XLSX)
if (Test-Path "$OUTPUT_FOLDER/XLSX/Storyline.xlsx")
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER/XLSX/Storyline.xlsx").Length)
    Write-Output "[Info]  File Size (XLSX): $Size"
}

# Get End Time
$EndTime_XLSX = (Get-Date)

# Duration XLSX
$Time_XLSX = ($EndTime_XLSX-$StartTime_XLSX)
('Duration XLSX Creation:    {0} h {1} min {2} sec' -f $Time_XLSX.Hours, $Time_XLSX.Minutes, $Time_XLSX.Seconds) >> "$OUTPUT_FOLDER/Stats.txt"

}

#endregion Analysis

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Statistics

Function Get-Statistics {

# Get Start Time
$script:StartTime_Stats = (Get-Date)

# File Metadata
[int]$Count = (& $SQLite3 -readonly $DBPath "SELECT COUNT(*) FROM Storyline WHERE (Type LIKE '%birth%' OR Type LIKE '%accessed%' OR Type LIKE '%modified%')")
$FileMeta = '{0:N0}' -f $Count
Write-Output "[Info]  $FileMeta File Metadata Change(s) found"

# Install Logs (Aftermath Collection: \Artifacts\raw\logs\system_logs\install.log)
[int]$Count = (& $SQLite3 -readonly $DBPath "SELECT COUNT(*) FROM Storyline WHERE Type LIKE '%INSTALL%'")
$INSTALL = '{0:N0}' -f $Count
Write-Output "[Info]  $INSTALL Install Log Record(s) found"

# System Logs (Aftermath Collection: \Artifacts\raw\logs\system_logs\system.log)
[int]$Count = (& $SQLite3 -readonly $DBPath "SELECT COUNT(*) FROM Storyline WHERE Type LIKE '%SYSLOG%'")
$SYSLOG = '{0:N0}' -f $Count
Write-Output "[Info]  $SYSLOG System Log Record(s) found"

# Safari History (Aftermath Collection: \Browser\Safari\history_output.csv)
[int]$Count = (& $SQLite3 -readonly $DBPath "SELECT COUNT(*) FROM Storyline WHERE Type LIKE '%safari_history%'")
$SafariHistory = '{0:N0}' -f $Count
Write-Output "[Info]  $SafariHistory Safari History Record(s) found"

# Transparency, Consent, and Control (TCC)
[int]$Count = (& $SQLite3 -readonly $DBPath "SELECT COUNT(*) FROM Storyline WHERE Type LIKE '%tcc_%'")
$TCC = '{0:N0}' -f $Count
Write-Output "[Info]  $TCC TCC Database Change(s) found"

# XProtect Behavioral Service (XBS)
[int]$Count = (& $SQLite3 -readonly $DBPath "SELECT COUNT(*) FROM Storyline WHERE Type LIKE '%xpdb_%'")
$XPDB = '{0:N0}' -f $Count
Write-Output "[Info]  $XPDB XProtect Behavioral Service Record(s) found"

# XProtect Remediator Logs (Aftermath Collection: \UnifiedLog\xprotect_remediator.txt)
[int]$Count = (& $SQLite3 -readonly $DBPath "SELECT COUNT(*) FROM Storyline WHERE Type LIKE '%XPROTECT_REMEDIATOR%'")
$XPR = '{0:N0}' -f $Count
Write-Output "[Info]  $XPR XProtect Remediator Record(s) found"

# Get End Time
$EndTime_Stats = (Get-Date)

# Duration Stats
$Time_Stats = ($EndTime_Stats-$StartTime_Stats)
('Duration Stats Creation:   {0} h {1} min {2} sec' -f $Time_Stats.Hours, $Time_Stats.Minutes, $Time_Stats.Seconds) >> "$OUTPUT_FOLDER/Stats.txt"

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
    $MessageBody = "Status: Aftermath Storyline Analysis completed."
    $MessageTitle = "Storyline-Analyzer.ps1 (https://lethal-forensics.com/)"
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
    Write-Host "  Storyline Analysis completed successfully!    " -ForegroundColor Green
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
Invoke-Processing
Get-DatabaseViews
Get-Reports
Invoke-Excel
Get-Statistics
Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################
