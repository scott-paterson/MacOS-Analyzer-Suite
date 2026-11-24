# TCC-Analyzer v0.4
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
# jq v1.7.1 (2023-12-13)
# https://github.com/jqlang/jq
#
# SQLite Tools
# Windows: https://sqlite.org/download.html
# macOS: Built-in (sqlite3)
#
#
# Changelog:
# Version 0.1
# Release Date: 2024-07-18
# Initial Release
#
# Version 0.2
# Release Date: 2024-08-01
# Fixed: Minor Bug Fixes and Improvements
#
# Version 0.3
# Release Date: 2024-11-20
# Fixed: Minor Bug Fixes and Improvements
#
# Version 0.4
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
  TCC-Analyzer v0.4 - Automated Processing of TCC Database for DFIR

.DESCRIPTION
  TCC-Analyzer.ps1 is a PowerShell script utilized to simplify the processing of the TCC.db database (Transparency, Consent, and Control --> Application permissions) for DFIR.

.PARAMETER OutputDir
  Specifies the output directory. Default is "$HOME/Desktop/TCC-Analyzer" (macOS) or "$env:USERPROFILE\Desktop\TCC-Analyzer" (Windows).

  Note: The subdirectory 'TCC-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the TCC.db database.

.EXAMPLE
  PS> ./TCC-Analyzer.ps1

.EXAMPLE
  PS> ./TCC-Analyzer.ps1 -Path "$HOME/Desktop/TCC.db"

.EXAMPLE
  PS> ./TCC-Analyzer.ps1 -Path "/path/to/TCC.db" -OutputDir "/path/to/output"

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
        $script:OUTPUT_FOLDER = "$HOME/Desktop/TCC-Analyzer"
    }
    else
    {
        $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\TCC-Analyzer"
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
        $script:OUTPUT_FOLDER = Join-Path $OutputDir "TCC-Analyzer"
    }
}

# Tools

# jq
if ($script:OnMacOS -or $script:OnLinux)
{
    # Check for jq in PATH (installed via Homebrew or package manager)
    $script:jq = (Get-Command jq -ErrorAction SilentlyContinue).Source
    if (-not $script:jq)
    {
        $script:jq = "/opt/homebrew/bin/jq"
        if (-not (Test-Path $script:jq))
        {
            $script:jq = "/usr/local/bin/jq"
        }
    }
}
else
{
    $script:jq = "$SCRIPT_DIR\Tools\jq\jq-windows-amd64.exe"
}

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
$Host.UI.RawUI.WindowTitle = "TCC-Analyzer v0.4 - Automated Processing of TCC Database for DFIR"

# Check if the PowerShell script is being run with elevated privileges
if ($script:OnMacOS -or $script:OnLinux)
{
    # On macOS/Linux, check if running as root or with sudo
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

# Check if jq exists
if (!(Test-Path "$($jq)"))
{
    Write-Host "[Error] jq NOT found." -ForegroundColor Red
    if ($script:OnMacOS)
    {
        Write-Host "[Info]  Install with: brew install jq" -ForegroundColor Yellow
    }
    elseif ($script:OnLinux)
    {
        Write-Host "[Info]  Install with: sudo apt install jq" -ForegroundColor Yellow
    }
    Exit
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

# Select TCC Database
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
            $OpenFileDialog.Filter = "TCC Database|TCC.db|All Files (*.*)|*.*"
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
            $picked = Select-FileMacOS -Prompt "Select TCC.db"
            if ($picked)
            {
                $script:DatabaseFile = $picked
            }
            else
            {
                Write-Host ""
                Write-Host "[Info]  Please provide the path to the TCC.db database file." -ForegroundColor Cyan
                Write-Host "[Info]  Common locations:" -ForegroundColor Cyan
                Write-Host "        - /Library/Application Support/com.apple.TCC/TCC.db (System)" -ForegroundColor Gray
                Write-Host "        - ~/Library/Application Support/com.apple.TCC/TCC.db (User)" -ForegroundColor Gray
                Write-Host ""
                $script:DatabaseFile = Read-Host "Enter path to TCC.db"
            }
        }
        else
        {
            # Linux - Prompt for path
            Write-Host ""
            Write-Host "[Info]  Please provide the path to the TCC.db database file." -ForegroundColor Cyan
            Write-Host ""
            $script:DatabaseFile = Read-Host "Enter path to TCC.db"
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
Write-Output "TCC-Analyzer v0.4 - Automated Processing of TCC Database for DFIR"
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

# TCC Database
# Location: /Library/Application Support/com.apple.TCC/TCC.db (System)
# Location: ~/Library/Application Support/com.apple.TCC/TCC.db (User)

Function TCC {

# Input-Check
if (!(Test-Path "$DatabaseFile" -PathType Leaf))
{
    Write-Host "[Error] $DatabaseFile does not exist." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check File Extension
$Extension = [IO.Path]::GetExtension($DatabaseFile)
if (!($Extension -eq ".db" ))
{
    Write-Host "[Error] No TCC.db provided." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

$FileName = [IO.Path]::GetFileName($DatabaseFile)
Write-Output "[Info]  Processing TCC Database ($FileName) ..."
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

# Copy TCC.db to Output Directory
Copy-Item -Path "$DatabaseFile" -Destination "$OUTPUT_FOLDER/TCC.db"

# SQLite
# Get SQLite Metadata
$Name            = & $SQLite3 -readonly "$OUTPUT_FOLDER/TCC.db" "SELECT name FROM sqlite_master WHERE type='table' AND name='access';" 2>&1 # access
$Database        = & $SQLite3 -readonly "$OUTPUT_FOLDER/TCC.db" "PRAGMA database_list;" 2>&1 # main
$SchemaVersion   = & $SQLite3 -readonly "$OUTPUT_FOLDER/TCC.db" "PRAGMA main.schema_version;" 2>&1 # 25
$ApplicationID   = & $SQLite3 -readonly "$OUTPUT_FOLDER/TCC.db" "PRAGMA main.application_id;" 2>&1 # 0
$UserVersion     = & $SQLite3 -readonly "$OUTPUT_FOLDER/TCC.db" "PRAGMA user_version;" 2>&1 # user_version = TCC.db Version (7-22)
$Encoding        = & $SQLite3 -readonly "$OUTPUT_FOLDER/TCC.db" "PRAGMA encoding;" 2>&1 # UTF-8
$JournalMode     = & $SQLite3 -readonly "$OUTPUT_FOLDER/TCC.db" "PRAGMA journal_mode;" 2>&1 # wal
$IntegrityCheck  = & $SQLite3 -readonly "$OUTPUT_FOLDER/TCC.db" "PRAGMA integrity_check;" 2>&1 # ok

Write-Output "[Info]  TCC.db Version: $UserVersion (PRAGMA user_version)"

# Column Header Check
$ColumnHeaderCheck = & $SQLite3 -readonly "$OUTPUT_FOLDER/TCC.db" "PRAGMA table_info(access);"

# TCC.db (UserVersion 7-16)
if ($UserVersion -lt 17)
{
    # Get Data
    $Query = "SELECT service,client,client_type,auth_value,auth_reason,indirect_object_identifier FROM access;"
    $Data = (& $SQLite3 -separator ',' -readonly "$OUTPUT_FOLDER/TCC.db" "$Query" 2>&1) -replace "^", "Service,Client,Client Type,Authorization Value,Authorization Reason,Indirect Object Identifier`n" | ConvertFrom-Csv
}
# TCC.db (UserVersion 17-21)
elseif (($UserVersion -gt 16) -And ($UserVersion -lt 22))
{
    # Get Data
    $Query = "SELECT service,client,client_type,auth_value,auth_reason,indirect_object_identifier,last_modified FROM access;"
    $Data = (& $SQLite3 -separator ',' -readonly "$OUTPUT_FOLDER/TCC.db" "$Query" 2>&1) -replace "^", "Service,Client,Client Type,Authorization Value,Authorization Reason,Indirect Object Identifier,Last Modified`n" | ConvertFrom-Csv
}
# TCC.db (UserVersion 22+)
elseif ($UserVersion -gt 21)
{
    # Get Data
    $Query = "SELECT service,client,client_type,auth_value,auth_reason,indirect_object_identifier,last_modified,pid_version,boot_uuid FROM access;"
    $Data = (& $SQLite3 -separator ',' -readonly "$OUTPUT_FOLDER/TCC.db" "$Query" 2>&1) -replace "^", "Service,Client,Client Type,Authorization Value,Authorization Reason,Indirect Object Identifier,Last Modified,PID Version,Boot UUID`n" | ConvertFrom-Csv
}

# Count Records
$Count = ($Data | Measure-Object).Count
Write-Output "[Info]  Processing $Count records ..."

# Get TCC-Services.csv
$TCC_Services_Path = Join-Path $SCRIPT_DIR "Config/TCC-Services.csv"
if (Test-Path "$TCC_Services_Path")
{
    $TCC_Services = Import-Csv "$TCC_Services_Path" -Delimiter "," -Encoding UTF8
}

# Processing data
$Results = [Collections.Generic.List[PSObject]]::new()
ForEach($Record in $Data)
{
    # Service
    $ServiceValue = $Record.Service

    # Client
    $Client = $Record.Client

    # Client_Type
    $Client_Type_Value = $Record.'Client Type'
    switch($Client_Type_Value)
    {
        "0"     { $Client_Type = "0 - BundleID" }
        "1"     { $Client_Type = "1 - Absolute Path" }
        default { $Client_Type = "$Client_Type_Value - Unknown" }
    }

    # Authorization Value
    $Auth_Value = $Record.'Authorization Value'
    switch($Auth_Value)
    {
        "0" { $Authorization_Value = "0 - Access Denied" }
        "1" { $Authorization_Value = "1 - Unknown" }
        "2" { $Authorization_Value = "2 - Access Allowed" }
        "3" { $Authorization_Value = "3 - Access Limited" }
        "4" { $Authorization_Value = "4 - Access Limited" }
        default { $Authorization_Value = "$Auth_Value - Unknown" }
    }

    # Authorization Reason
    $Auth_Reason = $Record.'Authorization Reason'
    switch($Auth_Reason)
    {
        "0"  { $Authorization_Reason = "0 - Unknown" }
        "1"  { $Authorization_Reason = "1 - Error" }
        "2"  { $Authorization_Reason = "2 - User Consent" }
        "3"  { $Authorization_Reason = "3 - User Set" }
        "4"  { $Authorization_Reason = "4 - System Set" }
        "5"  { $Authorization_Reason = "5 - Service Policy" }
        "6"  { $Authorization_Reason = "6 - MDM Policy" }
        "7"  { $Authorization_Reason = "7 - Override Policy" }
        "8"  { $Authorization_Reason = "8 - Missing Usage String" }
        "9"  { $Authorization_Reason = "9 - Prompt Timeout" }
        "10" { $Authorization_Reason = "10 - Preflight Unknown" }
        "11" { $Authorization_Reason = "11 - Entitled" }
        "12" { $Authorization_Reason = "12 - App Type Policy" }
        default { $Authorization_Reason = "$Auth_Reason - Unknown" }
    }

    # Indirect Object Identifier
    $IndirectObjectIdentifier = $Record.'Indirect Object Identifier'

    # Last Modified
    if ($Record.'Last Modified')
    {
        $LastModified = $Record.'Last Modified'
        $EpochDate = [DateTime]"1/1/1970"
        $TimeZone = [TimeZoneInfo]::FindSystemTimeZoneById('UTC')
        $Last_Modified_UTC = [TimeZoneInfo]::ConvertTimeFromUtc($EpochDate.AddSeconds($LastModified), $TimeZone).ToString("yyyy-MM-dd HH:mm:ss")
    }
    else
    {
        $Last_Modified_UTC = ""
    }

    # PID Version
    $PIDVersion = $Record.'PID Version'

    # Boot UUID
    $BootUUID = $Record.'Boot UUID'

    # Client --> Service Name
    $ServiceName = ($TCC_Services | Where-Object {$_.Service -eq "$ServiceValue"}).'Service Name'

    # Client --> Description
    $Description = ($TCC_Services | Where-Object {$_.Service -eq "$ServiceValue"}).Description

    $Line = [PSCustomObject]@{
        "Service"                       = $ServiceValue
        "Service Name"                  = $ServiceName
        "Client"                        = $Client
        "Client Type"                   = $Client_Type
        "Authorization Value"           = $Authorization_Value
        "Authorization Reason"          = $Authorization_Reason
        "Indirect Object Identifier"    = $IndirectObjectIdentifier
        "Last Modified (UTC)"           = $Last_Modified_UTC
        "PID Version"                   = $PIDVersion
        "Boot UUID"                     = $BootUUID
        "Description"                   = $Description
    }

    $Results.Add($Line)
}

$Results | Export-Csv -Path "$OUTPUT_FOLDER/CSV/TCC.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if ($script:EnableExcel -and (Test-Path "$OUTPUT_FOLDER/CSV/TCC.csv"))
{
    if ((Get-Item "$OUTPUT_FOLDER/CSV/TCC.csv").Length -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER/CSV/TCC.csv" -Delimiter ","
        $Import | Export-Excel -Path "$OUTPUT_FOLDER/XLSX/TCC.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "TCC" -CellStyleSB {
        param($WorkSheet)
        if ($script:UseExcelStyling)
        {
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-F and H-J
            $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["H:J"].Style.HorizontalAlignment="Center"
        }
        }
    }
}

# File Size (XLSX)
if ($script:EnableExcel -and (Test-Path "$OUTPUT_FOLDER/XLSX/TCC.xlsx"))
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER/XLSX/TCC.xlsx").Length)
    Write-Output "[Info]  File Size (XLSX): $Size"
}

}

#endregion Analysis

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region iTunes

# iTunes Search API
# https://affiliate.itunes.apple.com/resources/documentation/itunes-store-web-service-search-api/
# https://developer.apple.com/library/archive/documentation/AudioVideo/Conceptual/iTuneSearchAPI/index.html
# https://itunes.apple.com/lookup?bundleId=com.skype.skype&country=US

# Note: The bundleId is a unique identifier for an app on the App Store. The limit is set to one result per query.

Function Get-AppInfo {

# Check Internet connectivity
if ($script:OnMacOS -or $script:OnLinux)
{
    $Connected = Test-Connection -ComputerName "itunes.apple.com" -Count 1 -Quiet -ErrorAction SilentlyContinue
}
else
{
    $Connected = (Test-NetConnection -ComputerName "itunes.apple.com" -Port 443).TcpTestSucceeded
}

if ($Connected -eq $true)
{
    if (Test-Path "$OUTPUT_FOLDER/CSV/TCC.csv")
    {
        # Data
        $Data = Import-Csv "$OUTPUT_FOLDER/CSV/TCC.csv" -Delimiter ","

        # Count Bundle IDs
        $BundleIDs = ($Data | Select-Object Client -Unique | Measure-Object).Count

        # Initializing Progress
        $i = 0

        $Results = [Collections.Generic.List[PSObject]]::new()
        ForEach($Record in $Data)
        {
            $Client = $Record.Client

            # Increment Progress Indicator
            $i++
            $percent = 0
            if ([int]$BundleIDs -gt 0)
            {
                $percent = [int][Math]::Min(100, [Math]::Floor(($i / [double]$BundleIDs) * 100))
            }
            Write-Progress -Activity "Processing BundleID" -Status "$i of $BundleIDs" -PercentComplete $percent

            if ($Client -like "*.*")
            {
                $BundleID = $Record.Client

                try
                {
                    $Response = Invoke-RestMethod -Uri "https://itunes.apple.com/lookup?bundleId=$BundleID&country=US" -Method Get -ErrorAction SilentlyContinue
                    $ResultCount = $Response.resultCount

                    if ($ResultCount -gt 0)
                    {
                        $ArtistName = $Response.results.artistName
                        $TrackName = $Response.results.trackName
                    }
                    else
                    {
                        $ArtistName = ""
                        $TrackName = ""
                    }
                }
                catch
                {
                    $ArtistName = ""
                    $TrackName = ""
                }
            }
            else
            {
                $BundleID = ""
                $ArtistName = ""
                $TrackName = ""
            }

            $Line = [PSCustomObject]@{
                "Service"                       = $Record.Service
                "Service Name"                  = $Record.'Service Name'
                "Client"                        = $Record.Client
                "Client Type"                   = $Record.'Client Type'
                "Authorization Value"           = $Record.'Authorization Value'
                "Authorization Reason"          = $Record.'Authorization Reason'
                "Indirect Object Identifier"    = $Record.'Indirect Object Identifier'
                "Last Modified (UTC)"           = $Record.'Last Modified (UTC)'
                "PID Version"                   = $Record.'PID Version'
                "Boot UUID"                     = $Record.'Boot UUID'
                "Description"                   = $Record.Description
                "iTunes - Artist Name"          = $ArtistName
                "iTunes - Track Name"           = $TrackName
            }

            $Results.Add($Line)
        }

        $Results | Export-Csv -Path "$OUTPUT_FOLDER/CSV/TCC_iTunes.csv" -NoTypeInformation -Encoding UTF8

        # XLSX
        if ($script:EnableExcel -and (Test-Path "$OUTPUT_FOLDER/CSV/TCC_iTunes.csv"))
        {
            if ((Get-Item "$OUTPUT_FOLDER/CSV/TCC_iTunes.csv").Length -gt 0)
            {
                $Import = Import-Csv "$OUTPUT_FOLDER/CSV/TCC_iTunes.csv" -Delimiter ","
                $Import | Export-Excel -Path "$OUTPUT_FOLDER/XLSX/TCC_iTunes.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "TCC" -CellStyleSB {
                param($WorkSheet)
                if ($script:UseExcelStyling)
                {
                    # BackgroundColor and FontColor for specific cells of TopRow
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
                    # HorizontalAlignment "Center" of columns A-F and H-J
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:J"].Style.HorizontalAlignment="Center"
                }
                }
            }
        }
    }
}
else
{
    Write-Host "[Info]  Skipping iTunes lookup (No Internet connectivity)" -ForegroundColor Yellow
}

}

#endregion iTunes

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Stats

Function Get-Stats {

# Create Stats directory
New-Item "$OUTPUT_FOLDER/Stats" -ItemType Directory -Force | Out-Null

if (Test-Path "$OUTPUT_FOLDER/CSV/TCC.csv")
{
    $Data = Import-Csv "$OUTPUT_FOLDER/CSV/TCC.csv" -Delimiter ","
    $Total = ($Data | Measure-Object).Count

    # Client (Stats)
    if ($Total -ge 1)
    {
        $Stats = $Data | Group-Object Client | Select-Object @{Name='Client'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
        if ($script:EnableExcel)
        {
            $Stats | Export-Excel -Path "$OUTPUT_FOLDER/Stats/Client.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Client" -CellStyleSB {
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
            $Stats | Export-Csv -Path "$OUTPUT_FOLDER/Stats/Client.csv" -NoTypeInformation -Encoding UTF8
        }
    }

    # Service (Stats)
    if ($Total -ge 1)
    {
        $Stats = $Data | Group-Object Service | Select-Object @{Name='Service'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
        if ($script:EnableExcel)
        {
            $Stats | Export-Excel -Path "$OUTPUT_FOLDER/Stats/Service.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Service" -CellStyleSB {
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
            $Stats | Export-Csv -Path "$OUTPUT_FOLDER/Stats/Service.csv" -NoTypeInformation -Encoding UTF8
        }
    }

    # Authorization Value (Stats)
    if ($Total -ge 1)
    {
        $Stats = $Data | Group-Object "Authorization Value" | Select-Object @{Name='Authorization Value'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
        if ($script:EnableExcel)
        {
            $Stats | Export-Excel -Path "$OUTPUT_FOLDER/Stats/AuthorizationValue.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AuthorizationValue" -CellStyleSB {
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
            $Stats | Export-Csv -Path "$OUTPUT_FOLDER/Stats/AuthorizationValue.csv" -NoTypeInformation -Encoding UTF8
        }
    }

    # Authorization Reason (Stats)
    if ($Total -ge 1)
    {
        $Stats = $Data | Group-Object "Authorization Reason" | Select-Object @{Name='Authorization Reason'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
        if ($script:EnableExcel)
        {
            $Stats | Export-Excel -Path "$OUTPUT_FOLDER/Stats/AuthorizationReason.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AuthorizationReason" -CellStyleSB {
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
            $Stats | Export-Csv -Path "$OUTPUT_FOLDER/Stats/AuthorizationReason.csv" -NoTypeInformation -Encoding UTF8
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
    $MessageBody = "Status: TCC Analysis completed."
    $MessageTitle = "TCC-Analyzer.ps1 (https://lethal-forensics.com/)"
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
    Write-Host "  TCC Analysis completed successfully!  " -ForegroundColor Green
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
TCC
Get-AppInfo
Get-Stats
Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################
