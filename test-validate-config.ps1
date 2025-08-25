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
if ($cfg.ExternalLog -and ($cfg.ExternalLog.FallbackLocal -isnot [bool])) { $errors += 'ExternalLog.FallbackLocal should be boolean' }

if (-not ($cfg.Adapters -and $cfg.Adapters.ExcludePatterns)) { $errors += 'Adapters.ExcludePatterns missing' }

if (-not ($cfg.Safety -and $cfg.Safety.MaxDisableSeconds -and $cfg.Safety.HealthWaitSeconds)) { $errors += 'Safety.MaxDisableSeconds or Safety.HealthWaitSeconds missing' }

if ($cfg.Safety) {
    if ($cfg.Safety.MaxDisableSeconds -isnot [int]) { $errors += 'Safety.MaxDisableSeconds should be integer' }
    if ($cfg.Safety.HealthWaitSeconds -isnot [int]) { $errors += 'Safety.HealthWaitSeconds should be integer' }
    if ($cfg.Safety.RollbackOnNoIPv4 -isnot [bool]) { $errors += 'Safety.RollbackOnNoIPv4 should be boolean' }
}

if (-not ($cfg.Forensics -and $cfg.Forensics.HashChainFile)) { $errors += 'Forensics.HashChainFile missing' }

if ($errors.Count -gt 0) {
    Write-Host "CONFIG VALIDATION FAILED:`n" -ForegroundColor Red
    $errors | ForEach-Object { Write-Host " - $_" }
    exit 1
}

Write-Host "Config looks valid." -ForegroundColor Green
exit 0
