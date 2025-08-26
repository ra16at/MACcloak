# ┌────────────────────────────────────────────────────────────┐
# │ MACcloak: Forensic-Grade MAC Randomization Script          │
# │ Part 1: Initialization & Configuration                     │
# └────────────────────────────────────────────────────────────┘

param (
    [switch]$AuditMode,
    [switch]$VerboseLogs,
    [switch]$SetupSchedule,
    [switch]$ScanAdapters
)

# Load configuration
$configPath = Join-Path $PSScriptRoot "randomMAC.config.json"
if (-not (Test-Path $configPath)) {
    Write-Error "Configuration file not found: $configPath"
    exit 1
}

$config = Get-Content $configPath | ConvertFrom-Json

# Validate required config fields
if (-not $config.adapterExclusions -or -not $config.logVolumeLabels -or -not $config.healthWaitSeconds) {
    Write-Error "Missing required fields in config file."
    exit 1
}

# Prepare adapter exclusion regex
$exclusionRegex = ($config.adapterExclusions -join "|")

# Prepare log file path
$logDate = Get-Date -Format "yyyy-MM-dd"
$logFileName = "randomMAC-$logDate.jsonl"
$logPath = $null

foreach ($label in $config.logVolumeLabels) {
    $volume = Get-Volume | Where-Object { $_.FileSystemLabel -eq $label -and $_.DriveLetter }
    if ($volume) {
        $logPath = "$($volume.DriveLetter):\$logFileName"
        break
    }
}

if (-not $logPath) {
    $logPath = Join-Path $PSScriptRoot $logFileName
    if ($VerboseLogs) {
        Write-Warning "No external log volume found. Using local fallback: $logPath"
    }
}

# Load previous hash if available
$previousHash = ""
if (Test-Path $logPath) {
    $lastLine = Get-Content $logPath | Select-Object -Last 1
    if ($lastLine) {
        $lastEntry = $lastLine | ConvertFrom-Json
        $previousHash = $lastEntry.hash
    }
}

# Utility: Write log entry with chained hash
function Write-LogEntry {
    param (
        [hashtable]$entry
    )
    $entry.previousHash = $previousHash
    $json = $entry | ConvertTo-Json -Compress
    $entry.hash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($json))) -Algorithm SHA256).Hash
    $entry | ConvertTo-Json -Compress | Out-File $logPath -Append
    $global:previousHash = $entry.hash
}

# ┌────────────────────────────────────────────────────────────┐
# │ MACcloak: Adapter Scanner & Compatibility Check            │
# │ Part 2: Detection & Filtering                              │
# └────────────────────────────────────────────────────────────┘

function Get-CompatibleAdapters {
    $results = @()

    $adapters = Get-NetAdapter | Where-Object {
        $_.Status -eq "Up" -and $_.HardwareInterface -eq $true -and $_.Name -notmatch $exclusionRegex
    }

    foreach ($adapter in $adapters) {
        $name = $adapter.Name
        $desc = $adapter.InterfaceDescription
        $guid = $adapter.InterfaceGuid
        $supportsCIM = $false
        $supportsRegistry = $false

        # Check CIM support
        try {
            $props = Get-NetAdapterAdvancedProperty -Name $name -ErrorAction Stop
            if ($props.RegistryKeyword -contains "NetworkAddress") {
                $supportsCIM = $true
            }
        } catch {}

        # Check registry fallback
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
            $subKey = Get-ChildItem $regPath | Where-Object {
                (Get-ItemProperty "$regPath\$_").NetCfgInstanceId -eq $guid
            }
            if ($subKey) {
                $supportsRegistry = $true
            }
        } catch {}

        $status = if ($supportsCIM) {
            "✅ CIM spoofing supported"
        } elseif ($supportsRegistry) {
            "⚠️ Registry spoofing fallback available"
        } else {
            "❌ Spoofing not supported"
        }

        $results += [PSCustomObject]@{
            Name        = $name
            Description = $desc
            CIMSupport  = $supportsCIM
            RegistryFallback = $supportsRegistry
            Status      = $status
        }
    }

    return $results
}

# If user runs -ScanAdapters, show compatibility and exit
if ($ScanAdapters) {
    $scanResults = Get-CompatibleAdapters
    Write-Host "`n🔍 Adapter Compatibility Scan:`n"
    $scanResults | Format-Table -AutoSize
    exit 0
}

# ┌────────────────────────────────────────────────────────────┐
# │ MACcloak: MAC Generator & Spoofing Engine                  │
# │ Part 3: Randomization & Application                        │
# └────────────────────────────────────────────────────────────┘

function Generate-RandomMAC {
    # Locally administered MAC starts with 02
    $macBytes = @("02")
    for ($i = 1; $i -lt 6; $i++) {
        $macBytes += "{0:X2}" -f (Get-Random -Minimum 0 -Maximum 256)
    }
    return ($macBytes -join "")
}

function Set-RandomMAC {
    param (
        [string]$AdapterName,
        [string]$NewMAC
    )

    $success = $false
    $errorMessage = $null
    $methodUsed = "None"

    try {
        # Attempt CIM-based spoofing
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
    if ($success -and -not $AuditMode) {
        Disable-NetAdapter -Name $AdapterName -Confirm:$false
        Start-Sleep -Seconds 2
        Enable-NetAdapter -Name $AdapterName
    }

    return @{
        adapter = $AdapterName
        newMac = $NewMAC
        method = $methodUsed
        success = $success
        error = $errorMessage
    }
}

# ┌────────────────────────────────────────────────────────────┐
# │ MACcloak: Execution Loop & Health Check                    │
# │ Part 4: Adapter Spoofing & Logging                         │
# └────────────────────────────────────────────────────────────┘

$compatibleAdapters = Get-CompatibleAdapters | Where-Object {
    $_.CIMSupport -or $_.RegistryFallback
}

foreach ($adapter in $compatibleAdapters) {
    $name = $adapter.Name
    $newMac = Generate-RandomMAC

    if ($VerboseLogs) {
        Write-Host "`n🎲 Spoofing $name with MAC: $newMac"
    }

    $result = Set-RandomMAC -AdapterName $name -NewMAC $newMac

    # Health check: wait for IPv4
    $ipv4Healthy = $false
    if (-not $AuditMode -and $result.success) {
        $waitTime = $config.healthWaitSeconds
        for ($i = 0; $i -lt $waitTime; $i++) {
            Start-Sleep -Seconds 1
            $ip = (Get-NetIPAddress -InterfaceAlias $name -AddressFamily IPv4 -ErrorAction SilentlyContinue)
            if ($ip) {
                $ipv4Healthy = $true
                break
            }
        }

        # Rollback if no IPv4
        if (-not $ipv4Healthy) {
            if ($VerboseLogs) {
                Write-Warning "⚠️ No IPv4 after spoofing. Rolling back $name."
            }

            # Clear spoofed MAC
            try {
                Set-NetAdapterAdvancedProperty -Name $name -RegistryKeyword "NetworkAddress" -RegistryValue "" -NoRestart -ErrorAction SilentlyContinue
            } catch {
                # Fallback clear
                try {
                    $adapterObj = Get-NetAdapter -Name $name
                    $guid = $adapterObj.InterfaceGuid
                    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
                    $subKey = Get-ChildItem $regPath | Where-Object {
                        (Get-ItemProperty "$regPath\$_").NetCfgInstanceId -eq $guid
                    }
                    if ($subKey) {
                        Remove-ItemProperty "$regPath\$subKey" "NetworkAddress" -ErrorAction SilentlyContinue
                    }
                } catch {}
            }

            # Bounce adapter again
            Disable-NetAdapter -Name $name -Confirm:$false
            Start-Sleep -Seconds 2
            Enable-NetAdapter -Name $name
        }
    }

    # Log result
    $entry = @{
        timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        adapter   = $name
        newMac    = $newMac
        method    = $result.method
        success   = $result.success
        error     = $result.error
        ipv4Healthy = $ipv4Healthy
    }

    Write-LogEntry -entry $entry
}

# ┌────────────────────────────────────────────────────────────┐
# │ MACcloak: Scheduler Setup & Help Text                      │
# │ Part 5: Finalization & User Guidance                       │
# └────────────────────────────────────────────────────────────┘

function Setup-MACcloakSchedule {
    $taskName = "MACcloak_DailySpoof"
    $scriptPath = $MyInvocation.MyCommand.Path

    # Daily trigger
    $triggerDaily = New-ScheduledTaskTrigger -Daily -At 7:00am
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`""
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $taskName -Trigger $triggerDaily -Action $action -Principal $principal -Force

    # Optional startup trigger
    if ($config.scheduleAtStartup) {
        $triggerBoot = New-ScheduledTaskTrigger -AtStartup
        Register-ScheduledTask -TaskName "${taskName}_Startup" -Trigger $triggerBoot -Action $action -Principal $principal -Force
    }

    Write-Host "`n🗓️ MACcloak schedule created successfully."
    Write-Host "Daily spoofing will run at 7:00 AM as SYSTEM."
    if ($config.scheduleAtStartup) {
        Write-Host "Startup spoofing also enabled."
    }
    exit 0
}

# Run scheduler setup if requested
if ($SetupSchedule) {
    Setup-MACcloakSchedule
}

# Onboarding message for first-time users
if (-not ($AuditMode -or $ScanAdapters -or $SetupSchedule)) {
    Write-Host "`n🛡️ Welcome to MACcloak — forensic-grade MAC randomization."
    Write-Host "Your config is loaded, logging is active, and spoofing is ready."
    Write-Host "Use -AuditMode to simulate runs, or -VerboseLogs for debug output."
    Write-Host "Run -SetupSchedule to automate daily spoofing."
    Write-Host "Run -ScanAdapters to preview compatibility."
}