# DSStore-Analyzer v0.1
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
# DSStoreParser v0.2.1 (2019-07-25)
# https://github.com/nicoleibrahim/DSStoreParser
#
# ImportExcel v7.8.10 (2024-10-21)
# https://github.com/dfinke/ImportExcel
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
# Release Date: 2025-11-20
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
  DSStore-Analyzer v0.1 - Automated Forensic Analysis of DS_Store Files for DFIR

.DESCRIPTION
  DSStore-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of Desktop Service Store Files (.DS_Store).

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\DSStore-Analyzer".

  Note: The subdirectory 'DSStore-Analyzer' is automatically created.

.PARAMETER InputDir
  Specifies the path to the input directory.

.EXAMPLE
  PS> .\DSStore-Analyzer.ps1

.EXAMPLE
  PS> .\DSStore-Analyzer.ps1 -InputDir "$env:USERPROFILE\Desktop\DSStore_Data"

.EXAMPLE
  PS> .\FSEvents-Analyzer.ps1 -InputDir "H:\MacOS-Analyzer-Suite\DSStore_Data" -OutputDir "H:\MacOS-Analyzer-Suite"

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

# Colors / Styling (only supported on Windows)
$script:UseExcelStyling = $false
if ($script:OnWindows)
{
    Add-Type -AssemblyName System.Drawing
    $script:Green  = [System.Drawing.Color]::FromArgb(0,176,80) # Green
    $script:Orange = [System.Drawing.Color]::FromArgb(255,192,0) # Orange

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
        $script:OUTPUT_FOLDER = Join-Path (Join-Path $HOME "Desktop") "DSStore-Analyzer"
    }
    else
    {
        $script:OUTPUT_FOLDER = Join-Path (Join-Path $env:USERPROFILE "Desktop") "DSStore-Analyzer"
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
        $script:OUTPUT_FOLDER = Join-Path $OutputDir "DSStore-Analyzer"
    }
}

# Tools

# DSStoreParser by Nicole Ibrahim
$script:DSStoreParser = Join-Path $SCRIPT_DIR "Tools/DSStoreParser/DSStoreParser.exe"

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
        $script:xsv = "/opt/homebrew/bin/xsv"
        if (-not (Test-Path $script:xsv))
        {
            $script:xsv = "/usr/local/bin/xsv"
        }
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
$Host.UI.RawUI.WindowTitle = "DSStore-Analyzer v0.1 - Automated Forensic Analysis of DS_Store Files for DFIR"

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

# DSStoreParser + helper tools are Windows-only in this repo
if ($script:OnWindows -and (Test-Path $script:DSStoreParser))
{
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
        Write-Host "[Info]  Install (optional): brew install xsv" -ForegroundColor Yellow
        Exit
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

# Select folder containing .DS_Store Files
if(!($InputDir))
{
    if ($script:OnWindows)
    {
        # Windows - Use FolderBrowserDialog
        Add-Type -AssemblyName System.Windows.Forms
        Function Get-FolderPath($InitialDirectory)
        {
            [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
            $script:OpenFolderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
            $OpenFolderDialog.Description = 'Select a folder containing DS_Store File(s)'
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
            $picked = Select-FolderMacOS -Prompt "Select a folder containing DS_Store file(s)"
            if ($picked)
            {
                $script:FolderPath = $picked
            }
            else
            {
                Write-Host ""
                $script:FolderPath = Read-Host "Enter folder path containing DS_Store files"
            }
        }
        else
        {
            $script:FolderPath = Read-Host "Enter folder path containing DS_Store files"
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
Write-Output "DSStore-Analyzer v0.1 - Automated Forensic Analysis of DS_Store Files for DFIR"
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

# Count .DS_Store Files
[int]$Bud1 = "0"
$Files = (Get-ChildItem $FolderPath -Filter ".DS_Store" -Recurse).FullName
ForEach ($File in $Files)
{
    if ($PSEdition -eq "Core")
    {
        $Bytes = (Get-Content -Path $File -AsByteStream -ReadCount 1 -TotalCount 8 | Select-Object -SKip 4) # PowerShell 7
    }
    else
    {
        $Bytes = (Get-Content -Path $File -Encoding Byte -ReadCount 1 -TotalCount 8 | Select-Object -SKip 4) # PowerShell 5.1
    }

    $Signature = ([System.BitConverter]::ToString($Bytes)).Replace("-"," ")
    if ($Signature -eq "42 75 64 31") # Magic Bytes
    {
        $Bud1++
    }
}

$Count = '{0:N0}' -f $Bud1
Write-Output "[Info]  Processing $Bud1 DS_Store File(s) ..."

# Input Size
$InputSize = Get-FileSize((Get-ChildItem -Path "$FolderPath" -Filter ".DS_Store" -Recurse | Measure-Object Length -Sum).Sum)
Write-Output "[Info]  Total Input Size: $InputSize"

}

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Analysis

# Desktop Service Store Files (.DS_Store)

# Source: 13Cubed - https://www.youtube.com/watch?v=5VKTaFBlMcE

# Basics
# - Present in all versions of Mac OS X
#   - OSX 10.4 (Tiger) extended their use to include Spotlight related metadata
# - Similar to desktop.ini and ShellBags in Windows
# - Shows folders accessed within Finder (the macOS GUI)
# - Stores window view settings, icon positions, sorting preferences, windows sizes and positions, and other metadata
# - Files are created in the emclosing (parent) folder when viewed in Icon, List, or Gallery View, but NOT in Column View
# - Applies to local, external, and network locations

# Note: .Trash is protected by System Integrity Protection (SIP) --> csrutil status

# Caveats
# - Full paths are NOT included
#   - Trash Put Back Locations are noted exception
# - Timestamps are NOT included
#   - Parsing tools can derive some time-related information based upon file system timestamps for the .DS_Store files themselves
# - Data is volatile
#   - When a file is deleted/moved, its associated records are removed
#   - When a file is renamed, its associated records are renamed

Function Invoke-DSStoreInventory {

    $StartTime_Inventory = (Get-Date)
    Write-Output "[Info]  Creating .DS_Store inventory report (CSV) ..."

    $csvDir = Join-Path $script:OUTPUT_FOLDER "CSV"
    New-Item $csvDir -ItemType Directory -Force | Out-Null

    if ($script:EnableExcel)
    {
        $xlsxDir = Join-Path $script:OUTPUT_FOLDER "XLSX"
        New-Item $xlsxDir -ItemType Directory -Force | Out-Null
    }

    $files = Get-ChildItem -Path $script:FolderPath -Filter ".DS_Store" -Recurse -File -ErrorAction SilentlyContinue
    if (-not $files -or $files.Count -eq 0)
    {
        Write-Output "[Info]  No .DS_Store files found."
        return
    }

    $results = foreach ($f in $files)
    {
        $md5 = ""; $sha1 = ""; $sha256 = ""
        try { $md5 = (Get-FileHash -LiteralPath $f.FullName -Algorithm MD5).Hash } catch {}
        try { $sha1 = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA1).Hash } catch {}
        try { $sha256 = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash } catch {}

        [PSCustomObject]@{
            "Path"        = $f.FullName
            "SizeBytes"   = $f.Length
            "CreatedUtc"  = $f.CreationTimeUtc.ToString("yyyy-MM-dd HH:mm:ss")
            "ModifiedUtc" = $f.LastWriteTimeUtc.ToString("yyyy-MM-dd HH:mm:ss")
            "AccessedUtc" = $f.LastAccessTimeUtc.ToString("yyyy-MM-dd HH:mm:ss")
            "MD5"         = $md5
            "SHA1"        = $sha1
            "SHA256"      = $sha256
        }
    }

    $inventoryCsv = Join-Path $csvDir "DSStoreFiles.csv"
    $results | Export-Csv -Path $inventoryCsv -NoTypeInformation -Encoding UTF8
    Write-Output "[Info]  Wrote: $inventoryCsv"

    if ($script:EnableExcel -and (Test-Path $inventoryCsv))
    {
        $import = Import-Csv $inventoryCsv
        $outXlsx = Join-Path (Join-Path $script:OUTPUT_FOLDER "XLSX") "DSStoreFiles.xlsx"

        $import | Export-Excel -Path $outXlsx -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DS_Store Files" -CellStyleSB {
            param($WorkSheet)
            if ($script:UseExcelStyling)
            {
                Set-Format -Address $WorkSheet.Cells["A1:H1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            }
        }

        Write-Output "[Info]  Wrote: $outXlsx"
    }

    $EndTime_Inventory = (Get-Date)
    $Time_Inventory = ($EndTime_Inventory-$StartTime_Inventory)
    ('DS_Store inventory duration: {0} h {1} min {2} sec' -f $Time_Inventory.Hours, $Time_Inventory.Minutes, $Time_Inventory.Seconds) >> "$script:OUTPUT_FOLDER/Stats.txt"
}

Function Invoke-DSStoreParser {

$StartTime_DSStoreParser = (Get-Date)

# DSStoreParser by Nicole Ibrahim
if ($script:OnWindows -and (Test-Path "$($DSStoreParser)"))
{
    Write-Output "[Info]  Parsing Desktop Service Store File(s) w/ DSStoreParser ..."
    New-Item "$OUTPUT_FOLDER\DSStoreParser\Reports\TSV" -ItemType Directory -Force | Out-Null

    & $DSStoreParser -s "$FolderPath" -o "$OUTPUT_FOLDER\DSStoreParser\Reports\TSV" > "$OUTPUT_FOLDER\DSStoreParser\DSStoreParser.txt"
}
else
{
    Write-Host "[Info]  DSStoreParser.exe is Windows-only. Skipping DSStoreParser-based parsing." -ForegroundColor Yellow
    return
}

# Stats
if (Test-Path "$OUTPUT_FOLDER\DSStoreParser\DSStoreParser.txt")
{
    $LogFile = Get-Content "$OUTPUT_FOLDER\DSStoreParser\DSStoreParser.txt"

    # Record Parsed
    [int]$Parsed = $LogFile | Select-String -Pattern "Records Parsed:" | ForEach-Object{($_ -split "\s+")[-1]}
    $Count = '{0:N0}' -f $Parsed
    Write-Output "[Info]  $Count Records found"

    # Errors
    [int]$Errors = ($LogFile | Select-String -Pattern "Error:" | Measure-Object).Count
    if ($Errors -eq 0)
    {
        Write-Host "[Info]  Files with Errors: 0" -ForegroundColor Green
    }
    else
    {
        Write-Host "[Info]  Files with Errors: $Errors" -ForegroundColor Red
    }
}

# Reports
Write-Output "[Info]  Creating Reports ..."
New-Item "$OUTPUT_FOLDER\DSStoreParser\Reports\CSV" -ItemType Directory -Force | Out-Null
if ($script:EnableExcel)
{
    New-Item "$OUTPUT_FOLDER\DSStoreParser\Reports\XLSX" -ItemType Directory -Force | Out-Null
}

# Report Columns
# generated_path: The generated path using the location of the .DS_Store file and the record filename stored in the .DS_Store file.
# record_filename: The record filename stored in the .DS_Store file.
# record_type: One of 42 identified record types. Contains the 4 letter code of the record type as well as a description of the code.
# record_format: The format that the record data is stored in.
# record_data: The record data.
# src_create_time: The created timestamp of the source .DS_Store file.
# src_mod_time: The modified timestamp of the source .DS_Store file.
# src_acc_time: The accessed timestamp of the source .DS_Store file.
# src_metadata_change_time: The metadata change timestamp of the source .DS_Store file.
# src_permissions: The permissions, owner ID, and group ID of the source .DS_Store file.
# src_size: The size of the source .DS_Store file.
# block: The block within the .DS_Store that this record was parsed from.
# src_file: The location of the .DS_Store file this record was parsed from.

# All_Parsed_Report - Contains all parsed records
$All_Parsed_Report = (Get-ChildItem "$OUTPUT_FOLDER\DSStoreParser\Reports\TSV" | Where-Object { $_.BaseName -match "DS_Store-All_Parsed_Report" }).BaseName
if (Test-Path "$OUTPUT_FOLDER\DSStoreParser\Reports\TSV\$All_Parsed_Report.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\DSStoreParser\Reports\TSV\$All_Parsed_Report.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\DSStoreParser\Reports\TSV\$All_Parsed_Report.tsv" -Delimiter "`t" -Encoding UTF8

        # CSV (always)
        $IMPORT | Export-Csv -Path "$OUTPUT_FOLDER\DSStoreParser\Reports\CSV\All_Parsed_Report.csv" -NoTypeInformation -Encoding UTF8

        # XLSX (optional)
        if ($script:EnableExcel)
        {
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\DSStoreParser\Reports\XLSX\All_Parsed_Report.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "All Parsed Report" -CellStyleSB {
            param($WorkSheet)
            if ($script:UseExcelStyling)
            {
                # BackgroundColor and FontColor for specific cells of TopRow
                Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
                # HorizontalAlignment "Left" of column A
                $WorkSheet.Cells["E:E"].Style.HorizontalAlignment="Left"
                # HorizontalAlignment "Center" of columns A-D and F-M
                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["F:M"].Style.HorizontalAlignment="Center"
                # ConditionalFormatting - record_filename
                Add-ConditionalFormatting -Address $WorkSheet.Cells["B:B"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Drag into Terminal",$B1)))' -BackgroundColor Red # Drag-to-Terminal technique (to override Gatekeeper)
            }
            }
        }
    }
}

# File Size (XLSX)
if ($script:EnableExcel -and (Test-Path "$OUTPUT_FOLDER\DSStoreParser\Reports\XLSX\All_Parsed_Report.xlsx"))
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\DSStoreParser\Reports\XLSX\All_Parsed_Report.xlsx").Length)
    Write-Output "[Info]  File Size (XLSX): $Size"
}

# Access_Report - Contains records specific to folder accesses
$Access_Report = (Get-ChildItem "$OUTPUT_FOLDER\DSStoreParser\Reports\TSV" | Where-Object { $_.BaseName -match "DS_Store-Folder_Access_Report" }).BaseName
if (Test-Path "$OUTPUT_FOLDER\DSStoreParser\Reports\TSV\$All_Parsed_Report.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\DSStoreParser\Reports\TSV\$Access_Report.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\DSStoreParser\Reports\TSV\$Access_Report.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Csv -Path "$OUTPUT_FOLDER\DSStoreParser\Reports\CSV\Access_Report.csv" -NoTypeInformation -Encoding UTF8

        if ($script:EnableExcel)
        {
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\DSStoreParser\Reports\XLSX\Access_Report.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Access Report" -CellStyleSB {
            param($WorkSheet)
            if ($script:UseExcelStyling)
            {
                # BackgroundColor and FontColor for specific cells of TopRow
                Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
                # HorizontalAlignment "Left" of column A
                $WorkSheet.Cells["E:E"].Style.HorizontalAlignment="Left"
                # HorizontalAlignment "Center" of columns A-D and F-M
                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["F:M"].Style.HorizontalAlignment="Center"
            }
            }
        }
    }
}

# Miscellaneous_Info_Report - Contains other miscellaneous records parsed
$Miscellaneous_Info_Report = (Get-ChildItem "$OUTPUT_FOLDER\DSStoreParser\Reports\TSV" | Where-Object { $_.BaseName -match "DS_Store-Miscellaneous_Info_Report" }).BaseName
if (Test-Path "$OUTPUT_FOLDER\DSStoreParser\Reports\TSV\$Miscellaneous_Info_Report.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\DSStoreParser\Reports\TSV\$Miscellaneous_Info_Report.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\DSStoreParser\Reports\TSV\$Miscellaneous_Info_Report.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Csv -Path "$OUTPUT_FOLDER\DSStoreParser\Reports\CSV\Miscellaneous_Info_Report.csv" -NoTypeInformation -Encoding UTF8

        if ($script:EnableExcel)
        {
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\DSStoreParser\Reports\XLSX\Miscellaneous_Info_Report.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Miscellaneous Info Report" -CellStyleSB {
            param($WorkSheet)
            if ($script:UseExcelStyling)
            {
                # BackgroundColor and FontColor for specific cells of TopRow
                Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
                # HorizontalAlignment "Left" of column A
                $WorkSheet.Cells["E:E"].Style.HorizontalAlignment="Left"
                # HorizontalAlignment "Center" of columns A-D and F-M
                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["F:M"].Style.HorizontalAlignment="Center"
            }
            }
        }
    }
}

# Get End Time
$EndTime_DSStoreParser = (Get-Date)

# Duration DSStoreParser
$Time_DSStoreParser = ($EndTime_DSStoreParser-$StartTime_DSStoreParser)
('DSStoreParser duration:  {0} h {1} min {2} sec' -f $Time_DSStoreParser.Hours, $Time_DSStoreParser.Minutes, $Time_DSStoreParser.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#endregion Analyis

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Statistics

Function Get-Statistics {

# Get Start Time
$script:StartTime_Stats = (Get-Date)

# Stats
New-Item "$OUTPUT_FOLDER\DSStoreParser\Stats" -ItemType Directory -Force | Out-Null

# Data Import
$All_Parsed_Report = (Get-ChildItem "$OUTPUT_FOLDER\DSStoreParser\Reports\TSV" | Where-Object { $_.BaseName -match "DS_Store-All_Parsed_Report" }).BaseName
$Data = Import-Csv "$OUTPUT_FOLDER\DSStoreParser\Reports\TSV\$All_Parsed_Report.tsv" -Delimiter "`t" -Encoding UTF8

# Record Types (Stats)
# Note: There are 42 record types currently identified.
$Total = ($Data | Select-Object record_type | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Data | Group-Object record_type | Select-Object @{Name='Record Type'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Csv -Path "$OUTPUT_FOLDER\DSStoreParser\Stats\RecordType.csv" -NoTypeInformation -Encoding UTF8

    if ($script:EnableExcel)
    {
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER\DSStoreParser\Stats\RecordType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Record Type" -CellStyleSB {
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

    $RecordTypes = ($Data | Select-Object record_type -Unique | Measure-Object).Count
    Write-Output "[Info]  $RecordTypes Record Types found (42)"
}

# Get End Time
$EndTime_Stats = (Get-Date)

# Duration Stats
$Time_Stats = ($EndTime_Stats-$StartTime_Stats)
('Duration Stats Creation: {0} h {1} min {2} sec' -f $Time_Stats.Hours, $Time_Stats.Minutes, $Time_Stats.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

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

# Completion message
if ($script:OnWindows)
{
    Add-Type -AssemblyName System.Windows.Forms
    $MessageBody = "Status: DS_Store Analysis completed."
    $MessageTitle = "DSStore-Analyzer.ps1 (https://lethal-forensics.com/)"
    $ButtonType = "OK"
    $MessageIcon = "Information"
    [void][System.Windows.Forms.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon)
}
else
{
    Write-Output "[Info]  DS_Store analysis completed."
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
Invoke-DSStoreInventory

if ($script:OnWindows -and (Test-Path "$($script:DSStoreParser)"))
{
    Invoke-DSStoreParser
    # Statistics depend on DSStoreParser TSV output
    if (Test-Path "$OUTPUT_FOLDER\DSStoreParser\Reports\TSV")
    {
        Get-Statistics
    }
}
else
{
    Write-Host "[Info]  Inventory report was generated (CSV; XLSX optional)." -ForegroundColor Yellow
}
Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# Record Types indicating a Folder was Accessed
#
# BKGD: Finder Folder Background Picture
# bRsV: Browse in Selected View
# bwsp: Browser Window Settings
# dscl: Directory is Expanded in List View
# fdsc: Directory is Expanded in Limited Finder Window
# fwi0: Finder Window Information
# fwsw: Finder Window Sidebar Width
# fwvh: Finder Window Sidebar Height
# glvp: Gallery View Settings
# GRP0: Group Items By
# icgo: icgo. Unknown. Icon View?
# icsp: icsp. Unknown. Icon View?
# ICVO: Icon View Options
# icvo: Icon View Options
# icvp: Icon View Settings
# icvt: Icon View Text Size
# info: info: Unknown. Finder Info?:
# lssp: List View Scroll Position
# lsvC: List View Columns
# LSVO: List View Options
# lsvo: List View Options
# lsvp: List View Settings
# lsvP: List View Settings
# lsvt: List View Text Size
# pBB0: Finder Folder Background Image Bookmark
# pBBk: Finder Folder Background Image Bookmark
# pict: Background Image
# vSrn: Opened Folder in new tab
# vstl: View Style Selected

# Other Miscellaneous Record Types
#
# clip: Text Clipping
# cmmt: Finder Comments
# dilc: Desktop Icon Location
# extn: File Extension
# Iloc: Icon Location
# lg1S: Logical Size
# logS: Logical Size
# modD: Modified Date
# moDD: Modified Date
# ph1S: Physical Size
# phyS: Physical Size
# ptbL: Trash Put Back Location
# ptbN: Trash Put Back Name
