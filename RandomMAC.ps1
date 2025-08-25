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
# SIG # Begin signature block
# MIIb8wYJKoZIhvcNAQcCoIIb5DCCG+ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCdljOD9ouzn0uG
# Q34EIBqgQsP54iXF9o1g5ll405S6uqCCFkAwggMCMIIB6qADAgECAhBgwo2fp20L
# m0n7Y5fuxPp+MA0GCSqGSIb3DQEBCwUAMBkxFzAVBgNVBAMMDlJhbmRvbU1BQyBV
# c2VyMB4XDTI1MDgyNTA4NDUwNVoXDTI4MDgyNTA4NTUwNFowGTEXMBUGA1UEAwwO
# UmFuZG9tTUFDIFVzZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCu
# vt2D6GgdE4IY7MWX+rTaPjE7Urc9a1lv5WfXw16eUGLULY5g0x99vd/j6psgWjFU
# QALvIa59RgSkqtGoiLrkZMdfEWcPJy/4USafWwmjuplGGXIEYm5NvlAObXTRi3Kx
# GuzHVE/J7wkG9r//MKOM5WTj6Qog3wl9UlFP7ks8QIVDzohodOF0D6ZUCBaT13To
# XF2I15ufgTGqgFXsgkGHY3vi4j9HbtBtzxhsT6jWHSFxmn7XEl4voBR5vYvImPYo
# 15Qf9EL9KtboZSNtUUSLd1wp4PcSwkQ+L29iofXRWs95Sy/I8gRbMcCAXcBW8sd+
# NWQB9aeOkw/wM5/l+XmdAgMBAAGjRjBEMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
# DDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUhJSvctfq4IKFR7AsA6XSPa1YfJ8wDQYJ
# KoZIhvcNAQELBQADggEBAFAVX58zWwYw9F5MR6/KsYHLj3SegSWLCqK1ZNBCRnJ8
# uYfZZO4Pv1d9R086bzLFOs9dK6E2ch6U5EGonYCDIkHxW+M+r5wTL0WT44TONxVH
# gY9aJIundh/rPT7PTkwDYIqDzUp1VkLkvRHMwcbpNqF9Vd4QHgybdReeQrG+tLo1
# 3n3lAam3E0QmDCMHKwchqiG5JbNWUWEPKetoC3VuK0fYvDS6MVNXTs6IVgpy0qO9
# EaQBFwlH5RDvekLxFWB8glpegWk1aJSjaNwdff3ySIGUpNEHHa0xVAeNNchoKcUU
# fSSuFAXYsdVH/EaqnMZBk+AX+Re+J5JpARUGCQcs6E8wggWNMIIEdaADAgECAhAO
# mxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUw
# EwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20x
# JDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEw
# MDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE
# aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMT
# GERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprN
# rnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVy
# r2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4
# IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13j
# rclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4Q
# kXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQn
# vKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu
# 5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/
# 8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQp
# JYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFf
# xCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGj
# ggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/
# 57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8B
# Af8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6
# oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElE
# Um9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEB
# AHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0a
# FPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNE
# m0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZq
# aVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCs
# WKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9Fc
# rBjDTZ9ztwGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmG
# MA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5
# NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8G
# A1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBT
# SEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0
# eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+Ruw
# OnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4B
# t0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1U
# kxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTca
# arps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zb
# CclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnG
# pTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/
# AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v
# 5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoi
# wOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm
# 2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYD
# VR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04w
# HwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGG
# MBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcw
# AYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8v
# Y2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBD
# BgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNl
# cnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgB
# hv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Q
# h8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3
# YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQ
# wr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/
# wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81
# hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00
# TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNj
# qFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0
# cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9
# sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0
# LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2
# tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG
# 9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4x
# QTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQw
# OTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1
# OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYD
# VQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVy
# IDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q
# 6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPn
# Z8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSss
# p3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09
# ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98ok
# souTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+
# 3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsn
# qcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQ
# PdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbS
# LZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojT
# dS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoK
# RR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8E
# AjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTv
# b1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAww
# CgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRw
# Oi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQw
# OTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3Js
# My5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0
# MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZI
# AYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk
# 9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tsh
# gb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9m
# zskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQ
# BHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+
# YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0c
# Ksb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY
# 7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcboj
# BcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05o
# xYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskK
# PIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjd
# NXOCIUjsarfNZzGCBQkwggUFAgEBMC0wGTEXMBUGA1UEAwwOUmFuZG9tTUFDIFVz
# ZXICEGDCjZ+nbQubSftjl+7E+n4wDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGC
# NwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgR6bVTIFd
# +gaOb/M2nOJPtjhHeAplLsvAOtfrMjGAoAUwDQYJKoZIhvcNAQEBBQAEggEAi0ZE
# /sq0S/0l9gIrJ5GFLISXBbw/dGOfLi96/F0NejahCciZ2iC4XiqOdZTgT+7KIp2+
# eDGGCiRLrl8KGw1W4S5/nk9QrLVq1kon26gsLgzVi0O7YcNG+8pAPRINCsiaiuVg
# 6EovWPH33yHkUlDOgm6KkDgLaLe5Y16JjDOkYCec1G56ajTN3nlkwVP4d5CUzvHf
# xkngpiA5b0N/Nl/Rk1Gj27dwhYnbu4CU+ElouZPVPXJ9szZOUSFzb6yH3wwgUwRZ
# fqhxC53XZFo36OAxe4hIoLRWEVIFSGTsyy9eq4mThjnOuE6UiX+kRYak92dt9ZRB
# 4O6TSYF/IVqH8AgXIqGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYg
# MjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkq
# hkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNTA4MjUwODU1
# MDdaMC8GCSqGSIb3DQEJBDEiBCDV7708TCsZmnr+beiaPDft/FtVOUUs1b+uU+Rk
# V5ub8DANBgkqhkiG9w0BAQEFAASCAgC9PFkTzu1rs0JkLSG0uVJN7W1OnxS2naJs
# EW3uiXE2EERrBFnbocAaehH3v/hYx9mgPk/Udl/ZuYJojZeSNd3y9dKquCzvKILK
# Ezwzk8dmBB6qcF8MKrtCpr/T+dO6/J7dsZz7zAIJi+vN7ozxdL2obiNTGPkCMIfa
# f9+7Cw+gOElnI83Ixp+J7LiuMo8DUq5nnOTuq9jCZAQ2zEOzweZuMbsgBDvMkwRn
# BoJh4sB99W8fWG0nOAeNRMfJmTu6Lalmp7J8KyBwrTthqCjDFbiPUErNVrJJuAKP
# IGnKzYFG1COpGvWyPRJwQoMQaarruftxof6O6ogiaCVpuYugWEAOtilkpzT6hyOt
# YM8rXzNtpZDE8aTC+GXDH6Qu4RnY/RAiSaRJ+8L38PFUbgmorUIuX1FfhlIuKceU
# M5q0erzMsODIJRZAKOXB+eAiQmUZHmnmELmcFiyQMbJOY68awLX1Mbap1vyoPw9x
# i/CzPr+z0NKQpO1iQTyi5v1ybzpaNXeh9+QoiIhd7S1BVzr1G6hR/ZprcNlK0Ib3
# /VLB5/mOxai9ZQSWUx9MRB4/c7GO5FuwUvwMew5Rc6isETx9fbsPEh3lfQJK0Al9
# qghc07aQKRSviUJAM03xkWizO013v9e84CJpbWmGi2+b4OrZHe98k30lyduEFlv1
# BTwqFqjtTg==
# SIG # End signature block
