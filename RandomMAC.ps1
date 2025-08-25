<#
.SYNOPSIS
  MACcloak – Hardened MAC randomizer with tamper-evident logging, global scheduling, and built-in signing wizard.

.DESCRIPTION
  - Randomizes MAC addresses for physical adapters on schedule
  - Logs to external drive with hash-chain tamper detection
  - Safe rollback if no IPv4 after change
  - Interactive scheduling (-SetupSchedule)
  - Hassle-free signing wizard (-SignSelf)
  - First-run onboarding (-FirstRun)
  - Audit mode for testing without changes
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ConfigPath = "$PSScriptRoot\randomMAC.config.json",
    [switch]$AuditMode,
    [switch]$VerboseLogs,
    [switch]$SetupSchedule,
    [switch]$SignSelf,
    [switch]$FirstRun
)

# =========================
# FIRST-RUN ONBOARDING
# =========================
if ($FirstRun) {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║      MACcloak First‑Run Setup         ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This guided setup will:" -ForegroundColor Yellow
    Write-Host "  1. Sign this script with a trusted certificate"
    Write-Host "  2. Optionally set ExecutionPolicy to AllSigned"
    Write-Host "  3. Schedule MACcloak to run automatically"
    Write-Host ""

    & $PSCommandPath -SignSelf
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Signing step failed or cancelled. Exiting FirstRun." -ForegroundColor Red
        exit
    }

    & $PSCommandPath -SetupSchedule
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Scheduling step failed or cancelled. Exiting FirstRun." -ForegroundColor Red
        exit
    }

    Write-Host "[3/3] Setup complete!" -ForegroundColor Green
    Write-Host "MACcloak is now signed, trusted, and scheduled to run automatically."
    Write-Host "You can test it anytime with:" -ForegroundColor Yellow
    Write-Host "  .\randomMAC.ps1 -AuditMode" -ForegroundColor Cyan
    exit
}

# =========================
# SIGNING WIZARD (-SignSelf)
# =========================
if ($SignSelf) {
    Add-Type -AssemblyName System.Windows.Forms
    Write-Host ""
    Write-Host "╔══════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║      MACcloak Script Signing Tool    ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "We’ll sign your script with a trusted certificate so it runs securely under AllSigned policy." -ForegroundColor Yellow
    Write-Host ""

    # Step 1: Select script
    $defaultScript = $MyInvocation.MyCommand.Path
    $useDefault = Read-Host "Sign this script ($([System.IO.Path]::GetFileName($defaultScript)))? (Y/N)"
    if ($useDefault -match '^[Yy]') {
        $ScriptPath = $defaultScript
    } else {
        $ofd = New-Object System.Windows.Forms.OpenFileDialog
        $ofd.Filter = "PowerShell Scripts (*.ps1)|*.ps1"
        $ofd.Title = "Select the PowerShell script to sign"
        if ($ofd.ShowDialog() -ne 'OK') {
            Write-Host "❌ No file selected. Exiting." -ForegroundColor Red
            exit
        }
        $ScriptPath = $ofd.FileName
    }

    # Step 2: Find or create certificate
    $certs = Get-ChildItem Cert:\CurrentUser\My | Where-Object {
        $_.HasPrivateKey -and
        $_.NotAfter -gt (Get-Date) -and
        ($_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing")
    } | Sort-Object NotBefore -Descending

        # Step 3: Sign script
    Write-Host "[3/4] Signing script..." -ForegroundColor Cyan
    $signature = Set-AuthenticodeSignature -FilePath $ScriptPath -Certificate $cert -TimestampServer "http://timestamp.digicert.com" -HashAlgorithm SHA256

    # Step 4: Verify
    Write-Host "[4/4] Verifying signature..." -ForegroundColor Cyan
    $verify = Get-AuthenticodeSignature -FilePath $ScriptPath
    if ($verify.Status -eq 'Valid') {
        Write-Host "✅ Successfully signed: $ScriptPath" -ForegroundColor Green
        Write-Host "   Thumbprint: $($cert.Thumbprint)"
        Write-Host "   Timestamped by: $($signature.TimeStamperCertificate.Subject)"
        $setPolicy = Read-Host "Set ExecutionPolicy to AllSigned for LocalMachine? (Y/N)"
        if ($setPolicy -match '^[Yy]') {
            Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine -Force
            Write-Host "✅ ExecutionPolicy set to AllSigned." -ForegroundColor Green
        }
    } else {
        Write-Host "❌ Signing failed!" -ForegroundColor Red
        Write-Host "Status: $($verify.Status)"
        Write-Host "Message: $($verify.StatusMessage)"
    }
    exit
}

# =========================
# SCHEDULER WIZARD (-SetupSchedule)
# =========================
if ($SetupSchedule) {
    Write-Host "=== MACcloak Scheduler Setup ===" -ForegroundColor Cyan
    do {
        $timeInput = Read-Host "Enter daily run time (HH:MM, 24-hour format, local time)"
    } until ($timeInput -match '^(?:[01]?\d|2[0-3]):[0-5]\d$')

    $parts = $timeInput -split ':'
    $runHour = [int]$parts[0]
    $runMinute = [int]$parts[1]

    $startupChoice = Read-Host "Also run at every system startup? (Y/N)"
    $addStartup = $startupChoice -match '^[Yy]'

    $dailyTrigger = New-ScheduledTaskTrigger -Daily -At ([datetime]::Today.AddHours($runHour).AddMinutes($runMinute).TimeOfDay)
    $triggers = @($dailyTrigger)
    if ($addStartup) { $triggers += New-ScheduledTaskTrigger -AtStartup }

    $scriptPath = $MyInvocation.MyCommand.Path
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy AllSigned -File `"$scriptPath`""
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew

    Register-ScheduledTask -TaskName "MACcloak Auto" -Action $action -Trigger $triggers -RunLevel Highest -User "SYSTEM" -Description "MACcloak: Daily MAC randomization with forensic logging" -Force

    Write-Host "✅ Scheduled task 'MACcloak Auto' created successfully." -ForegroundColor Green
    Write-Host "Daily run time: $timeInput (local time)"
    if ($addStartup) { Write-Host "Also runs at every system startup." }

    exit
}

# =========================
# UTILITY FUNCTIONS
# =========================

function Write-Status {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    Write-Host "[$(Get-Date -f s)][$Level] $Message"
}

function Compute-Hash {
    param([string]$InputString)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
    $hashBytes = $sha.ComputeHash($bytes)
    return ($hashBytes | ForEach-Object { $_.ToString('x2') }) -join ""
}

function Get-PrevHash {
    param([string]$Path)
    if (Test-Path $Path) {
        return Get-Content $Path -Raw
    }
    return ""
}

function Set-PrevHash {
    param(
        [string]$Path,
        [string]$Hash
    )
    Set-Content -Path $Path -Value $Hash -NoNewline -Encoding ASCII
}

function New-RandomMac {
    $bytes = 1..6 | ForEach-Object { Get-Random -Minimum 0 -Maximum 255 }
    # Set locally administered bit, ensure unicast
    $bytes[0] = ($bytes[0] -bor 0x02) -band 0xFE
    return ($bytes | ForEach-Object { $_.ToString("X2") }) -join ""
}

function Get-EffectiveMac {
    param($Adapter)
    return ($Adapter.MacAddress -replace "[:\-]", "").ToUpper()
}

function Bounce-Adapter {
    param(
        $Adapter,
        [int]$MaxDisableSeconds = 45,
        [int]$HealthWaitSeconds = 20
    )
    $adapterName = $Adapter.Name
    Disable-NetAdapter -Name $adapterName -Confirm:$false
    Start-Sleep -Seconds 5
    Enable-NetAdapter -Name $adapterName -Confirm:$false

    $deadline = (Get-Date).AddSeconds($HealthWaitSeconds)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 1
        $currentAdapter = Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue
        if ($null -ne $currentAdapter -and $currentAdapter.Status -eq 'Up') {
            return $true
        }
    }
    return $false
}

function Has-IPv4 {
    param($Adapter)
    $ipAddresses = Get-NetIPAddress -InterfaceIndex $Adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
    return ($ipAddresses | Where-Object { $_.IPAddress }).Count -gt 0
}

# =========================
# MAIN RANDOMIZATION LOGIC
# =========================

# Load config
if (-not (Test-Path $ConfigPath)) {
    Write-Host "❌ Config file not found: $ConfigPath" -ForegroundColor Red
    exit 1
}
$cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json

# Determine log root
$vol = Get-Volume | Where-Object { $_.FileSystemLabel -in $cfg.ExternalLog.VolumeLabels } | Select-Object -First 1
$logRoot = if ($vol) { $vol.DriveLetter + ":\randomMAC" } elseif ($cfg.ExternalLog.FallbackLocal) { Join-Path $PSScriptRoot "logs" } else { throw "No log volume" }
if (!(Test-Path $logRoot)) { New-Item -ItemType Directory -Path $logRoot | Out-Null }

# Prepare log paths
$day = (Get-Date -f yyyy-MM-dd)
$paths = [pscustomobject]@{
    Json = Join-Path $logRoot "randomMAC-$day.jsonl"
    Text = Join-Path $logRoot "randomMAC-$day.log"
    Hash = Join-Path $logRoot $cfg.Forensics.HashChainFile
}
$prevHash = Get-PrevHash $paths.Hash

# Select adapters
$adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -ne "Disabled" } | Where-Object {
    $name = $_.Name + " " + $_.InterfaceDescription
    -not ($cfg.Adapters.ExcludePatterns | Where-Object { $name -match $_ })
}

if (-not $adapters) {
    Write-Status "No target adapters found." "WARN"
    exit 0
}

foreach ($a in $adapters) {
    $old = Get-EffectiveMac $a
    $entry = [ordered]@{
        ts      = (Get-Date).ToString("o")
        adapter = $a.Name
        desc    = $a.InterfaceDescription
        oldMac  = $old
        newMac  = $null
        success = $false
        error   = $null
    }

    if ($AuditMode) {
        $json = $entry | ConvertTo-Json -Compress
        $currHash = Compute-Hash "$prevHash|$json"
        $entry.hashPrev = $prevHash
        $entry.hashCurr = $currHash
        Add-Content $paths.Json ($entry | ConvertTo-Json -Compress)
        Add-Content $paths.Text "$old AUDIT"
        Set-PrevHash $paths.Hash $currHash
        $prevHash = $currHash
        continue
    }

    $new = New-RandomMac
    $entry.newMac = $new

    try {
        Set-NetAdapterAdvancedProperty -Name $a.Name -RegistryKeyword "NetworkAddress" -RegistryValue $new -NoRestart -ErrorAction Stop | Out-Null
    } catch {
        $entry.error = "Set failed"
        Add-Content $paths.Text "$old FAIL"
        continue
    }

    if (!(Bounce-Adapter $a -MaxDisableSeconds $cfg.Safety.MaxDisableSeconds -HealthWaitSeconds $cfg.Safety.HealthWaitSeconds)) {
        $entry.error = "Bounce fail"
        continue
    }

    $now = Get-EffectiveMac (Get-NetAdapter -Name $a.Name)
    if ($cfg.Safety.RollbackOnNoIPv4 -and !(Has-IPv4 $a)) {
        Set-NetAdapterAdvancedProperty -Name $a.Name -RegistryKeyword "NetworkAddress" -RegistryValue "" -NoRestart
        Bounce-Adapter $a
        $entry.error = "No IPv4, rolled back"
        continue
    }

    if ($now -ne $new) {
        $entry.error = "Mismatch"
        continue
    }

    $entry.success = $true
    $json = $entry | ConvertTo-Json -Compress
    $currHash = Compute-Hash "$prevHash|$json"
    $entry.hashPrev = $prevHash
    $entry.hashCurr = $currHash
    Add-Content $paths.Json ($entry | ConvertTo-Json -Compress)
    Add-Content $paths.Text "$old -> $new OK"
    Set-PrevHash $paths.Hash $currHash
    $prevHash = $currHash
}

Write-Status "Done"