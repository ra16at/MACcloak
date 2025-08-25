Add-Type -AssemblyName System.Windows.Forms

Write-Host "=== MACcloak Easy Sign ===" -ForegroundColor Cyan

# 1. Pick script file
$openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
$openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1"
$openFileDialog.Title = "Select the PowerShell script to sign"
if ($openFileDialog.ShowDialog() -ne 'OK') {
    Write-Host "❌ No file selected. Exiting." -ForegroundColor Red
    exit
}
$ScriptPath = $openFileDialog.FileName

# 2. Find valid code signing certs
$certs = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object {
        $_.HasPrivateKey -and
        $_.NotAfter -gt (Get-Date) -and
        ($_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing")
    } | Sort-Object NotBefore -Descending

if (-not $certs) {
    Write-Host "❌ No valid Code Signing certificate found." -ForegroundColor Red
    Write-Host "Tip: Run 'New-SelfSignedCertificate -Type CodeSigningCert' to create one." -ForegroundColor Yellow
    exit
}

# 3. Choose cert if more than one
if ($certs.Count -gt 1) {
    Write-Host "Multiple certificates found:" -ForegroundColor Yellow
    for ($i=0; $i -lt $certs.Count; $i++) {
        Write-Host ("[{0}] {1} (Thumbprint: {2}, Expires: {3})" -f ($i+1), $certs[$i].Subject, $certs[$i].Thumbprint, $certs[$i].NotAfter)
    }
    $choice = Read-Host "Select certificate number"
    if ($choice -notmatch '^\d+$' -or [int]$choice -lt 1 -or [int]$choice -gt $certs.Count) {
        Write-Host "❌ Invalid selection." -ForegroundColor Red
        exit
    }
    $cert = $certs[[int]$choice - 1]
} else {
    $cert = $certs[0]
    Write-Host "Using certificate: $($cert.Subject)" -ForegroundColor Green
}

# 4. Sign the script
Write-Host "Signing script..." -ForegroundColor Cyan
$signature = Set-AuthenticodeSignature -FilePath $ScriptPath -Certificate $cert -TimestampServer "http://timestamp.digicert.com" -HashAlgorithm SHA256

# 5. Show result
if ($signature.Status -eq 'Valid') {
    Write-Host "✅ Successfully signed: $ScriptPath" -ForegroundColor Green
    Write-Host "   Thumbprint: $($cert.Thumbprint)"
    Write-Host "   Timestamped by: $($signature.TimeStamperCertificate.Subject)"
} else {
    Write-Host "❌ Signing failed!" -ForegroundColor Red
    Write-Host "Status: $($signature.Status)"
    Write-Host "Message: $($signature.StatusMessage)"
}