# macOS Setup Guide

This guide explains how to set up and run the MacOS-Analyzer-Suite on macOS.

## Prerequisites

### 1. PowerShell Core

Install PowerShell on macOS:

```bash
# Using Homebrew
brew install powershell/tap/powershell

# Verify installation
pwsh --version
```

### 2. ImportExcel PowerShell Module (Optional)

```powershell
# In PowerShell
Install-Module -Name ImportExcel -Scope CurrentUser
```

XLSX output is **disabled by default**.

- If you want **CSV-only** (recommended): do nothing.
- If you want **XLSX output** (optional): install ImportExcel and run with `-NoExcel:$false`.

This applies to every script, including `KnockKnock-Analyzer.ps1` and `VirusTotal-Analyzer.ps1`. When KnockKnock-Analyzer or XProtect-Analyzer start a VirusTotal lookup, they pass the same `-NoExcel` setting through.

### 3. System Tools

Most scripts require SQLite (built-in on macOS) and optionally jq and xsv:

```bash
# Install jq (JSON processor) - required by KnockKnock-Analyzer
brew install jq

# Install xsv (CSV toolkit)
brew install xsv

# VirusTotal lookups (VirusTotal-Analyzer, and the optional lookup step in KnockKnock/XProtect)
brew install virustotal-cli yq
```

For VirusTotal lookups, put your API key in `Config.json` under `VirusTotal.APIKey`.

## Script Compatibility

| Script | macOS Support | Notes |
|--------|---------------|-------|
| TCC-Analyzer.ps1 | ✅ Full | Works natively |
| Quarantine-Analyzer.ps1 | ✅ Full | Works natively |
| XProtect-Analyzer.ps1 | ✅ Full | Works natively |
| BTM-Analyzer.ps1 | ✅ Full | Works natively |
| Timeline-Analyzer.ps1 | ✅ Full | Works natively |
| Storyline-Analyzer.ps1 | ✅ Full | Works natively |
| KnockKnock-Analyzer.ps1 | ✅ Full | Requires jq |
| VirusTotal-Analyzer.ps1 | ✅ Full | Requires `vt`, `yq`, and an API key |
| DSStore-Analyzer.ps1 | ⚠️ Partial | Requires DSStoreParser (see below) |
| FSEvents-Analyzer.ps1 | ⚠️ Partial | Python parser works; Rust parser is Windows-only |

## Running Scripts on macOS

### Basic Usage

```bash
# Navigate to the script directory
cd /path/to/MacOS-Analyzer-Suite

# Run with PowerShell
pwsh ./TCC-Analyzer.ps1 -Path ~/Library/Application\ Support/com.apple.TCC/TCC.db

# Or with specific output directory
pwsh ./TCC-Analyzer.ps1 -Path /path/to/TCC.db -OutputDir ~/Desktop/output
```

### TCC-Analyzer

Analyzes the TCC (Transparency, Consent, and Control) database.

```bash
# System TCC database (requires sudo)
sudo pwsh ./TCC-Analyzer.ps1 -Path "/Library/Application Support/com.apple.TCC/TCC.db"

# User TCC database
pwsh ./TCC-Analyzer.ps1 -Path "$HOME/Library/Application Support/com.apple.TCC/TCC.db"
```

### Quarantine-Analyzer

Analyzes the LSQuarantine database (download history).

```bash
pwsh ./Quarantine-Analyzer.ps1 -Path "$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
```

### XProtect-Analyzer

Analyzes the XProtect Behavioral Service database.

```bash
# Requires sudo for live system (macOS 13+)
sudo pwsh ./XProtect-Analyzer.ps1 -Path "/private/var/protected/xprotect/db/XPdb"

# Skip the VirusTotal prompt at the end
sudo pwsh ./XProtect-Analyzer.ps1 -Path "/private/var/protected/xprotect/db/XPdb" -skipVT
```

The `-wal` and `-shm` files next to `XPdb` are copied too, because recent events can still be in the write-ahead log.

### KnockKnock-Analyzer

Analyzes [KnockKnock](https://objective-see.org/products/knockknock.html) results (`KnockKnock_Results_yyyy-MM-dd.json`), including the verbose report format.

```bash
pwsh ./KnockKnock-Analyzer.ps1 -Path ~/Desktop/KnockKnock_Results_2026-11-24.json

# Skip the VirusTotal prompt at the end
pwsh ./KnockKnock-Analyzer.ps1 -Path ~/Desktop/KnockKnock_Results_2026-11-24.json -skipVT
```

### VirusTotal-Analyzer

Bulk hash lookup against VirusTotal from a `.txt` or `.log` file with one MD5, SHA1, or SHA256 per line. KnockKnock-Analyzer and XProtect-Analyzer call it for you if you answer "Yes" at the end.

```bash
pwsh ./VirusTotal-Analyzer.ps1 -Path ~/Desktop/KnockKnock-Analyzer/KnockKnock/MD5.txt
```

### BTM-Analyzer

Analyzes the Background Task Management dump (persistence mechanisms).

```bash
# First, create the BTM dump
sudo sfltool dumpbtm > ~/Desktop/btm.txt

# Then analyze it
pwsh ./BTM-Analyzer.ps1 -Path ~/Desktop/btm.txt
```

### Timeline-Analyzer

Analyzes Aftermath file timeline exports.

```bash
pwsh ./Timeline-Analyzer.ps1 -Path /path/to/file_timeline.csv
```

### Storyline-Analyzer

Analyzes Aftermath storyline exports.

```bash
pwsh ./Storyline-Analyzer.ps1 -Path /path/to/storyline.csv
```

## Partial Support Scripts

### DSStore-Analyzer

`DSStoreParser.exe` is Windows-only in this repo, so the full DSStoreParser-based parsing is skipped on macOS.

On macOS/Linux, `DSStore-Analyzer.ps1` still generates a **CSV inventory** of `.DS_Store` files (paths, size, timestamps, hashes). XLSX output is optional (requires ImportExcel and not using `-NoExcel`).

For deeper macOS-native parsing, consider:

- [ds_store Python module](https://github.com/al45tair/ds_store): `pip3 install ds_store`
- [DSStoreParser Python version](https://github.com/nicoleibrahim/DSStoreParser)

Future versions may integrate Python-based DS_Store parsing directly.

### FSEvents-Analyzer

The Rust-based parser (`fsevents_parser_rs.exe`) is Windows-only, but the Python-based parser (`FSEParser_V4.1.py`) works on macOS:

```bash
# Ensure Python 3 is installed
python3 --version

# The script will use FSEParser_V4.1.py for parsing
```

## Output Files

All scripts generate output to `~/Desktop/<ToolName>-Analyzer/` by default:

- `CSV/` - CSV format output (universal compatibility)
- `XLSX/` - Excel format output (**optional**; requires ImportExcel module and running with `-NoExcel:$false`)
- `Stats/` - Statistical summaries
- `Transcript.txt` - Session log

## Common Issues

### Permission Denied

Some macOS artifacts require elevated privileges:

```bash
# Use sudo for system-level databases
sudo pwsh ./TCC-Analyzer.ps1 -Path /Library/Application\ Support/com.apple.TCC/TCC.db
```

### SIP Protected Files

Some files are protected by System Integrity Protection (SIP). To analyze these from a live system, you may need to:

1. Boot to Recovery Mode
2. Disable SIP temporarily (not recommended for production systems)
3. Or analyze from a forensic image/offline copy

### File Not Found

Paths with spaces require escaping:

```bash
# Using backslash
pwsh ./TCC-Analyzer.ps1 -Path ~/Library/Application\ Support/com.apple.TCC/TCC.db

# Or using quotes
pwsh ./TCC-Analyzer.ps1 -Path "$HOME/Library/Application Support/com.apple.TCC/TCC.db"
```

## Differences from Windows

| Feature | Windows | macOS |
|---------|---------|-------|
| File dialogs | GUI dialogs | Native picker via `osascript` (fallback to prompts) |
| Completion message | MessageBox popup | Console output |
| Default paths | %USERPROFILE%\Desktop | $HOME/Desktop |
| Admin check | Windows Administrator | sudo/root (warning only) |
| Path separator | \ (backslash) | / (forward slash) |

## Contributing

When modifying scripts for cross-platform support:

1. Use `$HOME` instead of `$env:USERPROFILE`
2. Use forward slashes `/` in paths (works on both platforms)
3. Use `Join-Path` for path construction
4. Check `$IsMacOS` for platform-specific code
5. Avoid Windows-specific assemblies like `System.Windows.Forms`

