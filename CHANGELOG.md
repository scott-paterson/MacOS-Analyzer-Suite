# Changelog  

All changes to the MacOS-Analyzer-Suite will be documented in this file.  

## [Fork] - scott-paterson/MacOS-Analyzer-Suite (unreleased)
### Added
- Native macOS support (PowerShell 7) for all analyzers: OS detection, `osascript` file picker, Homebrew `sqlite3`/`jq`/`yq`/`vt`, `$HOME/Desktop` default output, forward-slash paths
- MACOS-SETUP.md
- XLSX output is opt-in in every analyzer (`-NoExcel:$false` with ImportExcel installed); CSV by default
- `-NoExcel` is passed through to VirusTotal-Analyzer from KnockKnock-Analyzer and XProtect-Analyzer
- XProtect-Analyzer copies `XPdb-wal`/`XPdb-shm` with the database

### Fixed
- XProtect-Analyzer: parsing used `ConvertFrom-String`, which does not exist in PowerShell 7
- Quarantine-Analyzer: commas in URLs/titles shifted columns; quarantine type labels follow the SANS FOR518 mapping
- sqlite3: use `-csv -header` (newer sqlite drops the header row with `-header -csv`)
- KnockKnock-Analyzer (PowerShell 7): Signature Status/Signer always "Unknown" (Int64 lookup keys), flagged item count always 0 (`=` instead of `-eq`), jq filters with Windows PowerShell 5.1 quoting
- VirusTotal-Analyzer: internet check used Windows-only APIs; summary and malicious-file alert only printed when ImportExcel was installed; "0 of N found" when all hashes were found
- TCC-Analyzer (macOS): internet check uses TCP 443 instead of ping
- TCC-Analyzer: a junk row (header values as data) was added after every record, and commas in values shifted columns
- No more `-NoTypeInformation is obsolete` warnings on PowerShell 7.4+
- SudoUsageActivity/BashActivity queries also match sudoers paths and zsh history

### Changed
- Authenticode signature blocks removed from modified scripts
- TCC-Analyzer: App Store (iTunes) lookup is opt-in with `-AppLookup`; by default no bundle IDs leave the machine

## [1.2.0] - 2026-03-16
### Added
- KnockKnock-Analyzer
- VirusTotal-Analyzer

### Fixed
- Minor fixes and improvements

## [1.1.0] - 2025-11-20
### Added
- BTM-Analyzer
- DSStore-Analyzer
- Storyline-Analyzer (Aftermath)
- Timeline-Analyzer (Aftermath)

### Fixed
- Minor fixes and improvements

## [1.0.0] - 2025-11-10
### Added
- FSEvents-Analyzer
- Quarantine-Analyzer
- TCC-Analyzer
- XProtect-Analyzer

### Changed
- CHANGELOG.md
