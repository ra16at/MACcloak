# MACcloak — Usage

This document shows a minimal, safe setup and usage guide for `RandomMAC.ps1`.

## Prerequisites
- Windows 10/11 or Windows Server with NetTCPIP / NetAdapter cmdlets.
- PowerShell 5.1 (Windows PowerShell) or PowerShell 7+.
- Administrative privileges for changing adapter settings or registering scheduled tasks.

## Quick install
1. Clone the repository (example):

```powershell
git clone https://github.com/ra16at/MACcloak.git "C:\Program Files\MACcloak"
Set-Location "C:\Program Files\MACcloak"
```

2. Validate the bundled config:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\test-validate-config.ps1
```

3. Edit `randomMAC.config.json` to match your environment (external volume labels, adapter exclude patterns, safety timeouts).

## Recommended: sign the script
To run under stricter ExecutionPolicy (AllSigned) sign `RandomMAC.ps1`. See `SIGNING.md`.

Verify signature:

```powershell
Get-AuthenticodeSignature -FilePath .\RandomMAC.ps1 | Format-List *
```

## Dry run (audit)
Test which adapters would be targeted without making changes:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\RandomMAC.ps1 -AuditMode
```

## Run for real (interactive)
Run as Administrator to allow adapter changes:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\RandomMAC.ps1
```

## Schedule a daily run (example)
Run elevated to register a SYSTEM-level scheduled task:

```powershell
$scriptPath = 'C:\Program Files\MACcloak\RandomMAC.ps1'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy AllSigned -File `"$scriptPath`\""
$trigger = New-ScheduledTaskTrigger -Daily -At 02:30
Register-ScheduledTask -TaskName 'MACcloak Auto' -Action $action -Trigger $trigger -RunLevel Highest -User 'SYSTEM' -Description 'MACcloak: Daily MAC randomization with forensic logging' -Force
```

If the script is not signed, change the action argument to use `-ExecutionPolicy Bypass` (less strict).

## Logs and forensics
- Logs are written under the configured external volume (label match) or `logs` fallback next to the script.
- JSONL logs: `randomMAC-YYYY-MM-DD.jsonl`
- Plain text logs: `randomMAC-YYYY-MM-DD.log`
- Hash chain file: configured via `randomMAC.config.json` (`Forensics.HashChainFile`).

Example to read JSONL:

```powershell
Get-Content .\logs\randomMAC-$(Get-Date -f yyyy-MM-dd).jsonl | ForEach-Object { $_ | ConvertFrom-Json }
```

## Uninstall
- Remove scheduled task (if created):

```powershell
Unregister-ScheduledTask -TaskName 'MACcloak Auto' -Confirm:$false
```

- Remove files and logs as needed.

## Troubleshooting
- "Cmdlets not found": run on Windows with NetTCPIP/NetAdapter modules.
- Permission errors: run PowerShell as Administrator.
- "Config file not found": ensure `randomMAC.config.json` is next to `RandomMAC.ps1` or pass `-ConfigPath`.
- Signature not `Valid`: re-sign or use `-ExecutionPolicy Bypass` for testing.

For deeper instructions see `README.md`, `instruction.me`, and `SIGNING.md`.
