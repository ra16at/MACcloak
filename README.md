
[![CI](https://github.com/ra16at/MACcloak/actions/workflows/verify.yml/badge.svg)](https://github.com/ra16at/MACcloak/actions/workflows/verify.yml) [![Release](https://img.shields.io/github/v/release/ra16at/MACcloak?label=latest%20release)](https://github.com/ra16at/MACcloak/releases/latest)

RandomMAC (MACcloak)
=====================

Purpose
-------
RandomMAC (a.k.a. MACcloak) randomizes physical network adapter MAC addresses on a schedule, writes tamper-evident logs to an external or local volume, and provides safety rollback if IPv4 connectivity fails.

Quick checklist (what you need)
------------------------------
- Windows 10/11 or Windows Server with PowerShell (Windows PowerShell 5.1 recommended or PowerShell 7+)
- NetTCPIP / NetAdapter cmdlets available (built into modern Windows)
- Administrative privileges for changing adapter settings, registering scheduled tasks, or importing certificates into machine stores
- The repository files in the same folder (`RandomMAC.ps1`, `randomMAC.config.json`, `SIGNING.md`)

Important: signing
------------------
For safety under stricter ExecutionPolicy settings you should sign `RandomMAC.ps1`. See `SIGNING.md` for full step-by-step commands. In short:

1. Create or locate a Code Signing certificate in `CurrentUser` (or use a CA-signed cert).
2. Sign the script with `Set-AuthenticodeSignature`.
3. Verify with `Get-AuthenticodeSignature`.
4. (Optional) Trust the certificate by importing the public cert into `CurrentUser\TrustedPeople` or `LocalMachine\TrustedPublisher` (requires Admin).

See `SIGNING.md` for copy-paste-ready commands.

Quick start (test run without changing MACs)
-------------------------------------------
Run an audit-only test to see which adapters the script would target and to confirm logging works:

```powershell
# change directory to where you install MACcloak (example):
cd "C:\Program Files\MACcloak"
# Dry run - does not change MACs
.\RandomMAC.ps1 -AuditMode
```

Run for real (recommended: sign the script first)
-------------------------------------------------
Run interactively as Administrator (changes adapter MACs):

```powershell
cd "C:\Program Files\MACcloak"
# Run with normal privileges (adapter changes require appropriate permissions)
.\RandomMAC.ps1
```

Non-interactive scheduling (example)
------------------------------------
Below is an example to register a daily scheduled task that runs the script as `SYSTEM` at 02:30 local time. Adjust the time and paths as needed (run as Administrator to register this task):

```powershell
$scriptPath = 'C:\Program Files\MACcloak\RandomMAC.ps1'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy AllSigned -File `"$scriptPath`""
$trigger = New-ScheduledTaskTrigger -Daily -At 02:30
Register-ScheduledTask -TaskName 'MACcloak Auto' -Action $action -Trigger $trigger -RunLevel Highest -User 'SYSTEM' -Description 'MACcloak: Daily MAC randomization with forensic logging' -Force
```

Configuration
-------------
`randomMAC.config.json` contains the settings the script reads on start (external log volume labels, adapter exclude patterns, safety timeouts, and forensics filename). Adjust this file to match your environment before first run.

Logging and forensics
---------------------
- The script writes JSONL and plain text logs under the selected log root (external volume or `logs` fallback).
- A small hashed state file (`hashchain.state` by default) is maintained for tamper-evident chaining.

Troubleshooting & common errors
-------------------------------
- "Config file not found": ensure `randomMAC.config.json` exists next to the script or pass `-ConfigPath` with the correct path.
- Cmdlets like `Get-NetAdapter` not found: run on a Windows machine with the NetTCPIP/NetAdapter cmdlets (modern Windows builds).
- Permission errors when changing adapter properties: run PowerShell as Administrator.
- Signature Status not `Valid`: re-check the signing step and ensure the certificate used is trusted by the account running the script.

Security notes
--------------
- Self-signed certificates are suitable for single-machine use. For distribution, use a CA-issued code-signing certificate.
- Importing a certificate into `LocalMachine` stores requires admin and affects trust for all users — only do this when you understand the implications.


Releasing (sign and publish)
----------------------------
When you're ready to publish a release that is signed by CI, do the following after you push the repository to GitHub and add the required secrets (`SIGNING_PFX` and `SIGNING_PFX_PASSWORD`):

1. Create an annotated tag locally and push it (PowerShell / cmd):

```powershell
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

2. The `release-and-sign.yml` workflow will run on the pushed tag, import the PFX from secrets, sign `RandomMAC.ps1`, and create a GitHub Release with the signed script and public cert attached.

Notes
- Make sure the repository name in GitHub matches the badge and README reference (`MACcloak`) or update the badge URL after renaming.
- Add the secrets (copy the base64 of your `.pfx` into `SIGNING_PFX` and the PFX password into `SIGNING_PFX_PASSWORD`) in the repository Settings → Secrets → Actions.

See the full release checklist: `.github/RELEASE_CHECKLIST.md`.


