<#
Quick config validator for randomMAC.config.json
Exits with code 0 on success, 1 on failure.
Intended for local testing or CI.
#>

$cfgPath = Join-Path $PSScriptRoot 'randomMAC.config.json'
if (-not (Test-Path $cfgPath)) {
    Write-Error "Config not found: $cfgPath"
    exit 1
}

try {
    $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-Error "Failed to parse JSON: $_"
    exit 1
}

$errors = @()

if (-not ($cfg.ExternalLog -and $cfg.ExternalLog.VolumeLabels)) { $errors += 'ExternalLog.VolumeLabels missing' }
if ($cfg.ExternalLog -and $null -eq $cfg.ExternalLog.FallbackLocal) { $errors += 'ExternalLog.FallbackLocal missing' }

if (-not ($cfg.Adapters -and $cfg.Adapters.ExcludePatterns)) { $errors += 'Adapters.ExcludePatterns missing' }

if (-not ($cfg.Safety)) { $errors += 'Safety section missing' }
else {
    if ($null -eq $cfg.Safety.MaxDisableSeconds) { $errors += 'Safety.MaxDisableSeconds missing' }
    if ($null -eq $cfg.Safety.HealthWaitSeconds) { $errors += 'Safety.HealthWaitSeconds missing' }

    # JSON numbers come back as System.Int64 or System.Double depending on parser. Accept numeric types.
    if ($cfg.Safety.MaxDisableSeconds -ne $null -and -not ($cfg.Safety.MaxDisableSeconds -is [int] -or $cfg.Safety.MaxDisableSeconds -is [long] -or $cfg.Safety.MaxDisableSeconds -is [double])) { $errors += 'Safety.MaxDisableSeconds should be numeric' }
    if ($cfg.Safety.HealthWaitSeconds -ne $null -and -not ($cfg.Safety.HealthWaitSeconds -is [int] -or $cfg.Safety.HealthWaitSeconds -is [long] -or $cfg.Safety.HealthWaitSeconds -is [double])) { $errors += 'Safety.HealthWaitSeconds should be numeric' }

    # Accept boolean-like values; ConvertTo-Json returns booleans as System.Boolean normally.
    if ($cfg.Safety.RollbackOnNoIPv4 -ne $null -and -not ($cfg.Safety.RollbackOnNoIPv4 -is [bool])) { $errors += 'Safety.RollbackOnNoIPv4 should be boolean' }
}
}

if (-not ($cfg.Forensics -and $cfg.Forensics.HashChainFile)) { $errors += 'Forensics.HashChainFile missing' }

if ($errors.Count -gt 0) {
    Write-Host "CONFIG VALIDATION FAILED:`n" -ForegroundColor Red
    $errors | ForEach-Object { Write-Host " - $_" }
    exit 1
}

Write-Host "Config looks valid." -ForegroundColor Green
exit 0
