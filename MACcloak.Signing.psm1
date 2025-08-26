function Sign-ScriptWithCert {
    Add-Type -AssemblyName System.Windows.Forms

    # Select script file
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1"
    $dialog.Title = "Select a PowerShell script to sign"
    if ($dialog.ShowDialog() -ne "OK") { return }

    $ScriptPath = $dialog.FileName

    # Find valid code signing certs
    $certs = Get-ChildItem Cert:\CurrentUser\My | Where-Object {
        $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) -and
        ($_.EnhancedKeyUsageList | Where-Object { $_.FriendlyName -eq "Code Signing" })
    }

    if (-not $certs) {
        Write-Warning "No valid code signing certificates found."
        return
    }

    # Choose cert if multiple
    $cert = if ($certs.Count -eq 1) {
        $certs[0]
    } else {
        $certs | ForEach-Object {
            Write-Host "$($_.Thumbprint) — $($_.Subject) — Expires $($_.NotAfter)"
        }
        $thumb = Read-Host "Enter thumbprint of certificate to use"
        $certs | Where-Object { $_.Thumbprint -eq $thumb }
    }

    if (-not $cert) {
        Write-Warning "Certificate not selected or invalid."
        return
    }

    # Sign the script
    $signature = Set-AuthenticodeSignature -FilePath $ScriptPath -Certificate $cert -TimestampServer "http://timestamp.digicert.com"

    # Display result
    Write-Host "`n🔏 Signing Result: $($signature.Status)"
    Write-Host "Message: $($signature.StatusMessage)"
    Write-Host "Certificate Thumbprint: $($cert.Thumbprint)"
}