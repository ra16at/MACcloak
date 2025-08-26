<#
.SYNOPSIS
  MACcloak – Hardened MAC randomizer with tamper-evident logging, global scheduling, and built-in signing wizard.

.DESCRIPTION
  - Randomizes MAC addresses for physical adapters on schedule
  - Logs to external drive with hash-chain tamper detection
  - Safe rollback if no IPv4 after change
  - Interactive scheduling (-SetupSchedule)
    - (Signing removed) Use instructions.me for manual signing
  - Audit mode for testing without changes
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ConfigPath = "$PSScriptRoot\randomMAC.config.json",
    [switch]$AuditMode,
    [switch]$VerboseLogs,
    [switch]$SetupSchedule
)

# First-run onboarding removed. See instruction.me for manual signing and scheduling steps.

# Interactive signing wizard removed. Use instruction.me for manual signing instructions.

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
    # Get-Random -Maximum is exclusive, so use 256 to allow 0-255
    $bytes = 1..6 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }
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


function Invoke-MACSpoof {
    param (
        [string]$AdapterName,
        [string]$NewMAC,
        [string]$PreviousHash = ""
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $success = $false
    $errorMessage = $null
    $methodUsed = "None"

    try {
        # Primary method: CIM-based spoofing
        Set-NetAdapterAdvancedProperty -Name $AdapterName -RegistryKeyword "NetworkAddress" -RegistryValue $NewMAC -NoRestart -ErrorAction Stop
        $methodUsed = "CIM"
        $success = $true
    } catch {
        # Fallback: Registry spoofing
        try {
            $adapter = Get-NetAdapter -Name $AdapterName
            $guid = $adapter.InterfaceGuid
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
            $subKey = Get-ChildItem $regPath | Where-Object {
                (Get-ItemProperty "$regPath\$_").NetCfgInstanceId -eq $guid
            }

            if ($subKey) {
                Set-ItemProperty "$regPath\$subKey" "NetworkAddress" $NewMAC
                $methodUsed = "Registry"
                $success = $true
            } else {
                $errorMessage = "Registry subkey not found for adapter $AdapterName"
            }
        } catch {
            $errorMessage = "Fallback registry method failed: $_"
        }
    }

    # Bounce adapter if spoofing succeeded
    if ($success) {
        Disable-NetAdapter -Name $AdapterName -Confirm:$false
        Start-Sleep -Seconds 2
        Enable-NetAdapter -Name $AdapterName
    }

    # Build log entry
    $logEntry = @{
        timestamp = $timestamp
        adapter = $AdapterName
        newMac = $NewMAC
        method = $methodUsed
        success = $success
        error = $errorMessage
        previousHash = $PreviousHash
    }

    # Chain hash
    $json = $logEntry | ConvertTo-Json -Compress
    $logEntry.hash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($json))) -Algorithm SHA256).Hash

    return $logEntry
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

# Find a volume matching one of the configured labels. Prefer volumes with a DriveLetter.
$volumes = Get-Volume | Where-Object { $_.FileSystemLabel -in $cfg.ExternalLog.VolumeLabels }
$vol = $volumes | Where-Object { $_.DriveLetter } | Select-Object -First 1
if (-not $vol) { $vol = $volumes | Select-Object -First 1 }

$logRoot = if ($vol) {
    if ($vol.DriveLetter) { $vol.DriveLetter + ":\randomMAC" }
    else { Join-Path $vol.Path "randomMAC" }
} elseif ($cfg.ExternalLog.FallbackLocal) { Join-Path $PSScriptRoot "logs" } else { throw "No log volume" }
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

