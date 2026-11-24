# VirusTotal-Analyzer
#
# This file is part of the MacOS-Analyzer-Suite.
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
# VirusTotal-CLI v1.3.0 (2026-02-17)
# https://github.com/VirusTotal/vt-cli
#
# yq v4.52.4 (2026-02-14)
# https://github.com/mikefarah/yq --> yq_windows_amd64.zip
#
#
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.6456) and PowerShell 5.1 (5.1.19041.6456)
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.6456) and PowerShell 7.5.5
# Tested on macOS with PowerShell 7.7 (fork: scott-paterson/MacOS-Analyzer-Suite)
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  VirusTotal-Analyzer - Bulk File Hash Check w/ VirusTotal

.DESCRIPTION
  VirusTotal-Analyzer.ps1 is a PowerShell script utilized to check a list of file hashes via VirusTotal API.

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\VirusTotal-Analyzer" (Windows) or "$HOME/Desktop/VirusTotal-Analyzer" (macOS).

  Note: The subdirectory 'VirusTotal-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the input file (MD5, SHA1, SHA256).

.PARAMETER NoExcel
  XLSX output is disabled by default (CSV only). To create XLSX as well, install the ImportExcel module and use -NoExcel:$false.

.EXAMPLE
  PS> .\VirusTotal-Analyzer.ps1

.EXAMPLE
  PS> .\VirusTotal-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\KnockKnock-Analyzer\KnockKnock\MD5.txt"

.EXAMPLE
  PS> .\VirusTotal-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\SHA1.txt" -OutputDir "H:\MacOS-Analyzer-Suite"

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
    $script:SCRIPT_DIR = $PSScriptRoot
}
else
{
    # PowerShell 2
    $script:SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

# Detect Operating System
# NOTE: Do NOT use names like IsWindows/IsMacOS/IsLinux here because PowerShell defines read-only automatic variables with those names.
$script:OnWindows = $true
$script:OnMacOS   = $false
if ($PSVersionTable.PSVersion.Major -ge 6)
{
    $script:OnWindows = $IsWindows
    $script:OnMacOS   = $IsMacOS
}

# Excel export toggle (optional)
$script:EnableExcel = $false
if (-not $NoExcel -and (Get-Module -ListAvailable -Name ImportExcel))
{
    $script:EnableExcel = $true
}

# Colors
Add-Type -AssemblyName System.Drawing
$script:Green  = [System.Drawing.Color]::FromArgb(0,176,80) # Green
$script:Orange = [System.Drawing.Color]::FromArgb(255,192,0) # Orange
$script:FileNotFoundColor = [System.Drawing.Color]::FromArgb(219,219,219) # Grey
$script:MaliciousColor    = [System.Drawing.Color]::FromArgb(255,0,0) # Red

# Output Directory
if (!($OutputDir))
{
    if ($script:OnWindows)
    {
        $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\VirusTotal-Analyzer" # Default
    }
    else
    {
        $script:OUTPUT_FOLDER = "$HOME/Desktop/VirusTotal-Analyzer" # Default
    }
}
else
{
    if ($OutputDir -cnotmatch '.+(?=[/\\])' -and $OutputDir -notmatch '^[/~]')
    {
        Write-Host "[Error] You must provide a valid directory path." -ForegroundColor Red
        Exit
    }
    else
    {
        $script:OUTPUT_FOLDER = Join-Path $OutputDir "VirusTotal-Analyzer" # Custom
    }
}

# Tools

# VirusTotal-CLI
if ($script:OnWindows) { $script:vt = "$SCRIPT_DIR\Tools\VirusTotal-CLI\vt.exe" } else { $script:vt = (Get-Command vt -ErrorAction SilentlyContinue).Source }

# yq
if ($script:OnWindows) { $script:yq = "$SCRIPT_DIR\Tools\yq\yq_windows_amd64.exe" } else { $script:yq = (Get-Command yq -ErrorAction SilentlyContinue).Source }

# Configuration File (JSON)
if(!(Test-Path "$PSScriptRoot/Config.json"))
{
    Write-Host "[Error] Config.json NOT found." -ForegroundColor Red
    Exit
}
else
{
    $Config = Get-Content "$PSScriptRoot/Config.json" | ConvertFrom-Json

    # BackgroundColor
    if ($Config.ImportExcel.BackgroundColor)
    {
        if ($Config.ImportExcel.BackgroundColor -cnotmatch '^(([0-1]?[0-9]?[0-9])|([2][0-4][0-9])|(25[0-5])),(([0-1]?[0-9]?[0-9])|([2][0-4][0-9])|(25[0-5])),(([0-1]?[0-9]?[0-9])|([2][0-4][0-9])|(25[0-5]))$') # <0-255>,<0-255>,<0-255>
        {
            Write-Host "[Error] You must provide a valid RGB Color Code." -ForegroundColor Red
            Return
        }
    }

    # Excel - Color Scheme
    $script:BackgroundColor = [System.Drawing.Color]$Config.ImportExcel.BackgroundColor
    $script:FontColor       = $Config.ImportExcel.FontColor

    # VirusTotal CLI - API Key
    $script:APIKey = $Config.VirusTotal.APIKey
}

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

# Windows Title
$script:DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "VirusTotal-Analyzer - Bulk File Hash Check w/ VirusTotal"

# Check if the PowerShell script is being run with admin rights
if ($script:OnWindows -and !([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "Error: This PowerShell script must be run with admin rights." -ForegroundColor Red
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
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

# Check if vt.exe exists
if (!$vt -or !(Test-Path "$($vt)"))
{
    Write-Host "[Error] VirusTotal CLI (vt) NOT found." -ForegroundColor Red
    if (!$script:OnWindows) { Write-Host "[Info]  Install: brew install virustotal-cli" }
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check if yq_windows_amd64.exe exists
if (!$yq -or !(Test-Path "$($yq)"))
{
    Write-Host "[Error] yq NOT found." -ForegroundColor Red
    if (!$script:OnWindows) { Write-Host "[Info]  Install: brew install yq" }
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check VirusTotal API Key 
if ("$APIKey" -eq "api_key")
{
    Write-Host "[Error] No VirusTotal API Key provided. Please add your personal <api_key> to 'Config.json'" -ForegroundColor Red
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
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
    Param ([long]$Size)
    If ($Size -gt 1TB) {[string]::Format("{0:0.00} TB", $Size / 1TB)}
    ElseIf ($Size -gt 1GB) {[string]::Format("{0:0.00} GB", $Size / 1GB)}
    ElseIf ($Size -gt 1MB) {[string]::Format("{0:0.00} MB", $Size / 1MB)}
    ElseIf ($Size -gt 1KB) {[string]::Format("{0:0.00} KB", $Size / 1KB)}
    ElseIf ($Size -gt 0) {[string]::Format("{0:0.00} Bytes", $Size)}
    Else {""}
}

# Function Test-VirusTotalReachable (macOS/Linux replacement for NetworkListManager and Test-NetConnection)
Function script:Test-VirusTotalReachable
{
    $Client = [System.Net.Sockets.TcpClient]::new()
    try
    {
        $Client.ConnectAsync("virustotal.com", 443).Wait(5000) -and $Client.Connected
    }
    catch
    {
        $false
    }
    finally
    {
        $Client.Dispose()
    }
}

# Select Input File (Plain Text)
if(!($Path))
{
    if ($script:OnMacOS)
    {
        $Picked = & osascript -e 'POSIX path of (choose file with prompt "Select hash list (.txt or .log)")' 2>$null
        if ([string]::IsNullOrWhiteSpace($Picked))
        {
            $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
            Exit
        }
        $script:InputFile = $Picked.Trim()
    }
    elseif (!$script:OnWindows)
    {
        Write-Host "[Error] Please provide the input file with -Path." -ForegroundColor Red
        Exit
    }
    else
    {
    Function Get-OpenFile($InitialDirectory)
    { 
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
        $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $OpenFileDialog.Title = "MacOS-Analyzer-Suite - Select your Input File"
        $OpenFileDialog.InitialDirectory = $InitialDirectory
        $OpenFileDialog.Filter = "Text Files (*.txt;*.log)|*.txt;*.log|All Files (*.*)|*.*"
        $OpenFileDialog.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost=$true; TopLevel=$true}))
        $OpenFileDialog.ReadOnlyChecked = $true
        $OpenFileDialog.Filename
        $OpenFileDialog.ShowHelp = $true
        $OpenFileDialog.Multiselect = $false
        $OpenFileDialog.CheckFileExists = $true
    }

    $Result = Get-OpenFile

    if($Result -eq "OK")
    {
        $script:InputFile = $Result[1]
    }
    else
    {
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }
    }
}
else
{
    $script:InputFile = $Path
}

# Create a record of your PowerShell session to a text file
Start-Transcript -Path "$OUTPUT_FOLDER/Transcript.txt"

# Add the required MessageBox class
if ($script:OnWindows) { Add-Type -AssemblyName System.Windows.Forms }

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

Write-Host ""
Write-Host "$Logo"
Write-Output ""

# Header
Write-Output "VirusTotal-Analyzer - Bulk File Hash Check w/ VirusTotal"
Write-Output "(c) 2026 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Analysis date (ISO 8601)
$AnalysisDate = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "Analysis date: $AnalysisDate UTC"
Write-Output ""

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# VirusTotal

# Check if File exists (1)
if (Test-Path "$InputFile")
{
    # Check if File exists (2)
    if ((Get-Item $InputFile) -is [System.IO.FileInfo])
    {
        # Check File Extension
        $Extension = [IO.Path]::GetExtension($InputFile)
        if (!($Extension -match "\.log|\.txt" ))
        {
            Write-Host "[Error] No supported File Type provided." -ForegroundColor Red
            Write-Output ""
            Stop-Transcript
            $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
            Exit
        }

        Write-Output "[Info]  Processing Input File ($InputFile) ..."

        # Extract Hash Value(s)
        $Filter = @("^[A-Fa-f0-9]{32}$","^[A-Fa-f0-9]{40}$","^[A-Fa-f0-9]{64}$")
        if (Get-Content "$InputFile" | Select-String -Pattern $Filter -NotMatch -Quiet)
        {
            # Hash List
            Write-Output "[Info]  Extracting Hash Value(s) ..."
            $FileName = Get-ChildItem $InputFile | Select-Object BaseName, Extension
            $BaseName = $FileName.BaseName
            $Extension = $FileName.Extension
            $OutputFile = $OUTPUT_FOLDER + "/" + $BaseName + "-cleaned" + $Extension
            $HashList = Get-Content "$InputFile" | Select-String -Pattern $Filter
            $HashList -replace '(?m)^\s*?\n' | Out-File "$OutputFile"

            # Count Hash Values (w/ thousands separators)
            $Lines = (Get-Content "$OutputFile" | Measure-Object).Count
            $Total = '{0:N0}' -f $Lines
            Write-Output "[Info]  Total lines: $Total"

            $HashList = "$OutputFile"
        }
        else
        {
            # Count Lines (w/ thousands separators)
            $Lines = (Get-Content "$InputFile" | Measure-Object).Count
            $Total = '{0:N0}' -f $Lines
            Write-Output "[Info]  Total lines: $Total"

            $HashList = $InputFile
        }

        # MD5
        $MD5 = (Get-Content "$HashList" | Select-String -Pattern "^[A-Fa-f0-9]{32}$" | Measure-Object).Count
        if ($MD5 -gt 0)
        {
            Write-Output "[Info]  $MD5 MD5 Hash Value(s) found"
        }

        # SHA1
        $SHA1 = (Get-Content "$HashList" | Select-String -Pattern "^[A-Fa-f0-9]{40}$" | Measure-Object).Count
        if ($SHA1 -gt 0)
        {
            Write-Output "[Info]  $SHA1 SHA1 Hash Value(s) found"
        }

        # SHA256
        $SHA256 = (Get-Content "$HashList" | Select-String -Pattern "^[A-Fa-f0-9]{64}$" | Measure-Object).Count
        if ($SHA256 -gt 0)
        {
            Write-Output "[Info]  $SHA256 SHA256 Hash Value(s) found"
        }

        # Split-File
        Function Split-File {

            Param(
                [Parameter(Mandatory=$True,Position=1,HelpMessage="File path")]
                [string]$Path,
                [Parameter(Mandatory=$True,HelpMessage="Batch size")]
                [int]$BatchSize
            )

            $strFilename = Get-ChildItem $Path | Select-Object BaseName, Extension

            $script:strBaseName = $strFilename.BaseName
            $script:strExtension = $strFilename.Extension

            $objFile = Get-Content $Path

            $Count = [math]::ceiling($objFile.Count/$BatchSize)

            $Length = "D" + ([math]::floor([math]::Log10($Count) + 1)).ToString()

            1 .. $Count | ForEach-Object {
                $i = $_.ToString($Length)
                $Offset = $BatchSize * ($_ - 1)
                $OutputFile = $OUTPUT_FOLDER + "/" + $strBaseName + "-" + $i + $strExtension
                If($_ -eq 1) {
                    $objFile | Select-Object -First $BatchSize | Out-File $OutputFile
                } Else {
                    $objFile | Select-Object -First $BatchSize -Skip $Offset | Out-File $OutputFile
                }
            }
        }

        # Split in 498 line batches
        if ($Lines -gt "498")
        {
            Write-Output "[Info]  Hash List will be splitted ..."
            Split-File "$HashList" -BatchSize 498

            $File1 = "$OUTPUT_FOLDER" + "/" + $strBaseName + "-1" + "$strExtension"
            $Count = (Get-Content "$File1" | Measure-Object).Count

            # Internet Connectivity Check (Vista+)
            if ($script:OnWindows) { $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]‘{DCB00C01-570F-4A9B-8D69-199FDBA5723B}’)).IsConnectedToInternet } else { $NetworkListManager = Test-VirusTotalReachable }

            # Offline
            if (!($NetworkListManager -eq "True"))
            {
                Write-Host "[Error] Your computer is NOT connected to the Internet." -ForegroundColor Red
            }

            # Online
            if ($NetworkListManager -eq "True")
            {
                # Check if VirusTotal.com is reachable
                if ($(if ($script:OnWindows) { (Test-NetConnection -ComputerName virustotal.com -Port 443).TcpTestSucceeded } else { Test-VirusTotalReachable }))
                {
                    $EstimatedTime = $Count / 4
                    Write-Host "[Info]  Checking the first $Count Hash Value(s) on VirusTotal (Estimated Time: $EstimatedTime min) ... "

                    $QUERY_LIST = Get-Content "$File1"

                    ForEach( $QUERY in $QUERY_LIST )
                    {
                        # Get information about files
                        New-Item "$OUTPUT_FOLDER/YAML" -ItemType Directory -Force | Out-Null
                        & $vt --apikey "$APIKey" file "$QUERY" > "$OUTPUT_FOLDER/YAML/$QUERY.yml" 2> $null
                        Start-Sleep -Seconds 15
                    }
                }
                else
                {
                    Write-Host "[Error] virustotal.com is NOT reachable. Please check your network connection and try again." -ForegroundColor Red
                }
            }
        }
        else
        {
            # Internet Connectivity Check (Vista+)
            if ($script:OnWindows) { $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]‘{DCB00C01-570F-4A9B-8D69-199FDBA5723B}’)).IsConnectedToInternet } else { $NetworkListManager = Test-VirusTotalReachable }

            # Offline
            if (!($NetworkListManager -eq "True"))
            {
                Write-Host "[Error] Your computer is NOT connected to the Internet." -ForegroundColor Red
            }

            # Online
            if ($NetworkListManager -eq "True")
            {
                # Check if VirusTotal.com is reachable
                if ($(if ($script:OnWindows) { (Test-NetConnection -ComputerName virustotal.com -Port 443).TcpTestSucceeded } else { Test-VirusTotalReachable }))
                {
                    $EstimatedTime = $Lines / 4
                    Write-Host "[Info]  Checking Hash Value(s) on VirusTotal (Estimated Time: $EstimatedTime min) ... "

                    $QUERY_LIST = Get-Content "$HashList"

                    ForEach( $QUERY in $QUERY_LIST )
                    {
                        # Get information about files
                        New-Item "$OUTPUT_FOLDER/YAML" -ItemType Directory -Force | Out-Null
                        & $vt --apikey "$APIKey" file "$QUERY" > "$OUTPUT_FOLDER/YAML/$QUERY.yml" 2> $null
                        Start-Sleep -Seconds 15
                    }
                }
                else
                {
                    Write-Host "[Error] virustotal.com is NOT reachable. Please check your network connection and try again." -ForegroundColor Red
                }
            }
        }

        # CSV
        Write-Output "[Info]  Creating VirusTotal Report ..."
        Get-ChildItem -Recurse -Force -ErrorAction SilentlyContinue "$OUTPUT_FOLDER/YAML" | Foreach-Object FullName | Foreach-Object {

        $FilePath = $_
                
        if ((Get-Item "$FilePath").Length -gt 0kb)
        {
            $Hash     = $_ | ForEach-Object{($_ -split "[\\/]")[-1]} | ForEach-Object{($_ -split "\.")[0]}
            $Name     = & $yq eval '.[0].meaningful_name' "$FilePath" 2> $null
            $FileType = & $yq eval '.[0].exiftool.FileType' "$FilePath" 2> $null 
            $MD5      = & $yq eval '.[0].md5' "$FilePath" 2> $null
            $SHA1     = & $yq eval '.[0].sha1' "$FilePath" 2> $null
            $SHA256   = & $yq eval '.[0].sha256' "$FilePath" 2> $null

            $Signers = & $yq eval '.[0].signature_info.signers' "$FilePath" 2> $null
            if ("$Signers" -eq "null")
            {
                $Signers = ""
            }

            $TeamID = & $yq eval '.[0].signature_info.TeamIdentifier' "$FilePath" 2> $null
            if ("$TeamID" -eq "null")
            {
                $TeamID = ""
            }

            $SignatureVerification = & $yq eval '.[0].signature_info.verified' "$FilePath" 2> $null # Signed, null, and "The digital signature of the object did not verify."
            if ("$SignatureVerification" -eq "null")
            {
                $SignatureVerification = "File is not signed."
            }

            $Tags = (& $yq eval '.[0].tags[]' "$FilePath") -join ", " 2> $null
            if ("$Tags" -eq "null")
            {
                $Tags = ""
            }

            $Magic = & $yq eval '.[0].magic' "$FilePath" 2> $null
            $LastAnalysisUnixSeconds = & $yq eval '.[0].last_analysis_date' "$FilePath" 2> $null
            $LastAnalysis = (([System.DateTimeOffset]::FromUnixTimeSeconds($LastAnalysisUnixSeconds)).DateTime).ToString("yyyy-MM-dd HH:mm:ss")
            $Unsupported = & $yq eval '.[0].last_analysis_stats.type-unsupported' "$FilePath" 2> $null
            $Undetected = & $yq eval '.[0].last_analysis_stats.undetected' "$FilePath" 2> $null
            $Total = [int]$Unsupported + [int]$Undetected
            $Malicious = & $yq eval '.[0].last_analysis_stats.malicious' "$FilePath" 2> $null
            $Positives = $Malicious
            $DetectionRatio = "$Malicious/$Undetected"
            $Suspicious = & $yq eval '.[0].last_analysis_stats.suspicious' "$FilePath" 2> $null
            $VTLink = "https://www.virustotal.com/gui/file/$SHA256/detection"
            $FirstSubmittedUnixSeconds = & $yq eval '.[0].first_submission_date' "$FilePath" 2> $null
            $FirstSubmitted = (([System.DateTimeOffset]::FromUnixTimeSeconds($FirstSubmittedUnixSeconds)).DateTime).ToString("yyyy-MM-dd HH:mm:ss")
            $LastSubmittedUnixSeconds = & $yq eval '.[0].last_submission_date' "$FilePath" 2> $null
            $LastSubmitted = (([System.DateTimeOffset]::FromUnixTimeSeconds($LastSubmittedUnixSeconds)).DateTime).ToString("yyyy-MM-dd HH:mm:ss")
            $TimesSubmitted = & $yq eval '.[0].times_submitted' "$FilePath" 2> $null
            $Size = & $yq eval '.[0].size' "$FilePath"
            $VotesHarmless = & $yq eval '.[0].total_votes.harmless' "$FilePath" 2> $null
            $VotesMalicious = & $yq eval '.[0].total_votes.malicious' "$FilePath" 2> $null

            $CodeInsights = (& $yq eval '.[0].crowdsourced_ai_results[].analysis' "$FilePath") -join ", " 2> $null
            if ("$CodeInsights" -eq "null")
            {
                $CodeInsights = ""
            }
        }
        else
        {
            $Hash = $_ | ForEach-Object{($_ -split "[\\/]")[-1]} | ForEach-Object{($_ -split "\.")[0]}
            $Name = "No matches found."
            $FileType = ""
            $MD5 = ""
            $SHA1 = ""
            $SHA256 = ""
            $Signers = ""
            $TeamID = ""
            $SignatureVerification = ""
            $Tags = ""
            $Magic = ""
            $LastAnalysis = ""
            $DetectionRatio = ""
            $VTLink = ""
            $FirstSubmitted = ""
            $LastSubmitted = ""
            $TimesSubmitted = ""
            $Size = ""
            $VotesHarmless = ""
            $VotesMalicious = ""
            $CodeInsights = ""
        }
            New-Object –TypeName PSObject -Property ([ordered]@{
            "Lookup Hash" = $Hash
            Name = $Name
            "File Type" = $FileType
            MD5 = $MD5
            SHA1 = $SHA1
            SHA256 = $SHA256
            Signers = $Signers | ForEach-Object { $_ -replace ";","," }
            TeamIdentifier = $TeamID
            SignatureVerification = $SignatureVerification
            Tags = $Tags
            Magic = $Magic
            "LastAnalysis (UTC)" = $LastAnalysis
            Positives = $Positives
            DetectionRatio = $DetectionRatio
            VTLink = $VTLink
            "First Submission" = $FirstSubmitted
            "Last Submission" = $LastSubmitted
            TimesSubmitted = $TimesSubmitted
            "FileSize (Bytes)" = $Size
            FileSize = Get-FileSize($Size)
            VotesHarmless = $VotesHarmless # Community Score
            VotesMalicious = $VotesMalicious # Community Score
            "Code Insights" = $CodeInsights
            })

        } | ConvertTo-Csv -Delimiter "," -NoTypeInformation | Out-File "$OUTPUT_FOLDER/VirusTotal-Report.csv"
    }
}
else
{
    Write-Host "[Error] Input File does not exist." -ForegroundColor Red
    Write-Output ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}


# XLSX
if ($script:EnableExcel)
{
    if (Test-Path "$OUTPUT_FOLDER/VirusTotal-Report.csv")
    {
        if ((Get-Item "$OUTPUT_FOLDER/VirusTotal-Report.csv").Length -gt 0kb)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER/VirusTotal-Report.csv" -Delimiter "," -Encoding UTF8
            $Positives = ($Import | Where-Object {$_.Positives -ne ""} | Where-Object {$_.Positives -ne "0"} | Measure-Object).Count 
            if ($Positives -ge 1)
            {
                $Import | Export-Excel -Path "$OUTPUT_FOLDER/VirusTotal-Report.xlsx" -AutoSize -BoldTopRow -FreezePane 2,4 -AutoFilter -WorkSheetname "VirusTotal" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                Set-Format -Address $WorkSheet.Cells["A1:W1"] -BackgroundColor $BackgroundColor -FontColor $FontColor

                # HorizontalAlignment "Center" of columns A, C-J, L-N and P-V
                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["C:J"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["L:N"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["P:V"].Style.HorizontalAlignment="Center"

                # HorizontalAlignment "Left" - Magic
                $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Left"

                # HorizontalAlignment "Right" - FileSize (Bytes)
                $WorkSheet.Cells["S:S"].Style.HorizontalAlignment="Right"

                # HorizontalAlignment "Center" of header
                $WorkSheet.Cells["K1:K1"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["S1:S1"].Style.HorizontalAlignment="Center"

                # Positives --> Conditional Formatting --> Color Scales --> Green-Yellow-Red Color Scale
                Add-ConditionalFormatting -Address $WorkSheet.Cells["M:M"] -WorkSheet $WorkSheet -RuleType 'ThreeColorScale' -Reverse

                # No matches found. --> Grey
                Add-ConditionalFormatting -Address $WorkSheet.Dimension.Address -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("No matches found.",$B1)))' -BackgroundColor $FileNotFoundColor

                # DetectionRatio: >=1|VT --> Font: Red
                $Cells = "N:N"
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("1/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("2/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("3/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("4/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("5/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("6/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("7/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("8/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("9/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("10/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("11/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("12/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("13/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("14/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("15/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("16/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("17/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("18/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("19/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("20/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("21/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("22/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("23/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("24/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("25/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("26/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("27/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("28/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("29/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("30/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("31/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("32/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("33/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("34/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("35/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("36/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("37/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("38/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("39/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("40/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("41/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("42/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("43/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("44/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("45/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("46/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("47/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("48/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("49/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("50/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("51/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("52/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("53/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("54/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("55/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("56/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("57/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("58/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("59/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("60/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("61/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("62/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("63/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("64/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("65/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("66/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("67/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("68/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("69/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("70/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("71/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("72/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("73/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("74/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("75/",$N1)))' -FontColor $MaliciousColor -Bold

                # SignatureVerification: File is not signed --> Font: Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("File is not signed",$I1)))' -FontColor $MaliciousColor

                # SignatureVerification: The digital signature of the object did not verify --> Font: Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("The digital signature of the object did not verify",$I1)))' -FontColor $MaliciousColor

                # SignatureVerification: Valid (Signed file, valid signature) --> Font: Green
                Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$I1)))' -FontColor $Green

                }
            }
            else
            {
                $Import | Export-Excel -Path "$OUTPUT_FOLDER/VirusTotal-Report.xlsx" -AutoSize -BoldTopRow -FreezePane 2,4 -AutoFilter -WorkSheetname "VirusTotal" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                Set-Format -Address $WorkSheet.Cells["A1:W1"] -BackgroundColor $BackgroundColor -FontColor $FontColor

                # HorizontalAlignment "Center" of columns A, C-J, L-N and P-V
                $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["C:J"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["L:N"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["P:V"].Style.HorizontalAlignment="Center"

                # HorizontalAlignment "Left" - Magic
                $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Left"

                # HorizontalAlignment "Right" - FileSize (Bytes)
                $WorkSheet.Cells["S:S"].Style.HorizontalAlignment="Right"

                # HorizontalAlignment "Center" of header
                $WorkSheet.Cells["K1:K1"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["S1:S1"].Style.HorizontalAlignment="Center"

                # Positives --> Green
                Add-ConditionalFormatting -Address $WorkSheet.Cells["M:M"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("0",$M1)))' -BackgroundColor $Green

                # No matches found. --> Grey
                Add-ConditionalFormatting -Address $WorkSheet.Dimension.Address -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("No matches found.",$B1)))' -BackgroundColor $FileNotFoundColor

                # DetectionRatio: >=1|VT --> Font: Red
                $Cells = "N:N"
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("1/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("2/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("3/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("4/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("5/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("6/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("7/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("8/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("9/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("10/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("11/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("12/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("13/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("14/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("15/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("16/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("17/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("18/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("19/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("20/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("21/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("22/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("23/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("24/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("25/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("26/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("27/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("28/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("29/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("30/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("31/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("32/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("33/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("34/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("35/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("36/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("37/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("38/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("39/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("40/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("41/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("42/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("43/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("44/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("45/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("46/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("47/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("48/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("49/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("50/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("51/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("52/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("53/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("54/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("55/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("56/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("57/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("58/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("59/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("60/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("61/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("62/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("63/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("64/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("65/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("66/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("67/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("68/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("69/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("70/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("71/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("72/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("73/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("74/",$N1)))' -FontColor $MaliciousColor -Bold
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("75/",$N1)))' -FontColor $MaliciousColor -Bold

                # SignatureVerification: File is not signed --> Font: Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("File is not signed",$I1)))' -FontColor $MaliciousColor

                # SignatureVerification: The digital signature of the object did not verify --> Font: Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("The digital signature of the object did not verify",$I1)))' -FontColor $MaliciousColor

                # SignatureVerification: Valid (Signed file, valid signature) --> Font: Green
                Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$I1)))' -FontColor $Green

                }
            }
        }
    }
}

# Stats
if ((Test-Path "$OUTPUT_FOLDER/VirusTotal-Report.csv") -and (Get-Item "$OUTPUT_FOLDER/VirusTotal-Report.csv").Length -gt 0kb)
{
    $Import = @(Import-Csv "$OUTPUT_FOLDER/VirusTotal-Report.csv" -Delimiter "," -Encoding UTF8)
    $Total = $Import.Count
    $Count = @($Import | Where-Object { $_.Name -eq "No matches found." }).Count
    if ($Count -gt 0)
    {
        Write-Host "[Info]  $Count of $Total Hash Value(s) NOT found."
    }
    else
    {
        Write-Host "[Info]  $Total of $Total Hash Value(s) found." -ForegroundColor Green
    }

    # Filter for files >=3|VT
    $Count = @($Import | Where-Object { $_.Positives -match '^\d+$' -and [int]$_.Positives -ge 3 }).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] $Count Malicious File(s) found (>=3|VT)" -ForegroundColor "Red"
    }
    else
    {
        Write-Host "[Info]  No Malicious File(s) found (>=3|VT)" -ForegroundColor "Green"
    }
}

# Notes
# - The Public API is limited to 500 requests per day and a rate of 4 requests per minute. --> max. 498 requests/day (Starting with 499 request/day you will receive auto-email about your consumed quoata).
# - Daily quotas are reset every day at 00:00 UTC. 
# - When you have reached your API quota, API requests will respond wuth 204 (APIv2) or 429 (API v3).

# Access level	Public
# Request rate	4 requests/minute
# Daily quota	500 requests/day

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Footer

# Get End Time
$endTime = (Get-Date)

# Echo Time elapsed
Write-Output ""
Write-Output "FINISHED!"
'Overall analysis duration: {0:hh} h {0:mm} min {0:ss} sec' -f ($endTime-$startTime)

# Stop logging
Write-Output ""
Stop-Transcript
Start-Sleep 0.5

# Cleaning up
if (Test-Path "$OUTPUT_FOLDER/Transcript.txt")
{
    $Filter = @("^vt\.exe","VirusTotal-Analyzer.*\.ps1","^\+","\+ CategoryInfo          : NotSpecified:","\+ FullyQualifiedErrorId : NativeCommandError","API host: www.virustotal.com","^File ","^In .*VirusTotal-CLI.ps1:.*25")
    $Clean = Get-Content "$OUTPUT_FOLDER/Transcript.txt" | Select-String -Pattern $Filter -NotMatch 
    $Clean | Set-Content "$OUTPUT_FOLDER/Transcript.txt"
}

# MessageBox UI
if ($script:OnWindows)
{
    $Form = New-Object System.Windows.Forms.Form
    $Form.TopMost = $true
    $MessageBody = "Status: VirusTotal Hash Lookups completed."
    $MessageTitle = "VirusTotal-Analyzer.ps1 (https://lethal-forensics.com/)"
    $ButtonType = "OK"
    $MessageIcon = "Information"
    $Result = [System.Windows.Forms.MessageBox]::Show($Form, $MessageBody, $MessageTitle, $ButtonType, $MessageIcon)

}

    # Reset Progress Preference
    $Global:ProgressPreference = $OriginalProgressPreference

    # Reset Windows Title
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################
