Signing RandomMAC.ps1
=====================

This document contains copy-paste-ready commands for creating a Code Signing certificate, signing `RandomMAC.ps1`, verifying the signature, and optionally trusting/exporting the certificate.

Run these in PowerShell. Use an elevated prompt (Run as Administrator) only when noted.

1) Change to the script folder

```powershell
cd "C:\Program Files\SecureScripts"
```

2) Find an existing Code Signing certificate (optional)

```powershell
Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.HasPrivateKey -and ($_.EnhancedKeyUsageList.FriendlyName -contains 'Code Signing') } | Select-Object Subject,Thumbprint,NotAfter
```

3) Create a self-signed code-signing cert (if needed)

```powershell
# Creates an exportable code-signing cert valid for 3 years in CurrentUser\My
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=RandomMAC User" -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(3)
$cert | Select Subject,Thumbprint,NotAfter
```

4) Sign the script

```powershell
# If you have $cert from step 3
Set-AuthenticodeSignature -FilePath .\RandomMAC.ps1 -Certificate $cert -HashAlgorithm SHA256 -TimestampServer "http://timestamp.digicert.com"

# Or select by thumbprint
$thumb = '<PASTE_THUMBPRINT_HERE>'
$cert = Get-ChildItem Cert:\CurrentUser\My\$thumb
Set-AuthenticodeSignature -FilePath .\RandomMAC.ps1 -Certificate $cert -HashAlgorithm SHA256 -TimestampServer "http://timestamp.digicert.com"
```

5) Verify the signature

```powershell
Get-AuthenticodeSignature -FilePath .\RandomMAC.ps1 | Format-List *
```

`Status : Valid` indicates the signature is cryptographically valid.

6) Trust the publisher (optional)

Add public cert to CurrentUser TrustedPeople (no elevation):

```powershell
$cert | Export-Certificate -FilePath .\randommac_pub.cer -Force
Import-Certificate -FilePath .\randommac_pub.cer -CertStoreLocation Cert:\CurrentUser\TrustedPeople
```

Or add to LocalMachine TrustedPublisher (requires Admin):

```powershell
$cert | Export-Certificate -FilePath C:\Windows\Temp\randommac_pub.cer -Force
Import-Certificate -FilePath C:\Windows\Temp\randommac_pub.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```

7) Export PFX for other machines (optional)

```powershell
$pw = Read-Host -AsSecureString "PFX password"
Export-PfxCertificate -Cert $cert -FilePath .\randommac_signer.pfx -Password $pw
```

8) Set ExecutionPolicy to AllSigned (requires Admin)

```powershell
Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine -Force
```

Notes
- Use a CA-signed code-signing cert for distributed software.
- Timestamping preserves signature validity after cert expiry.
- Importing into LocalMachine stores affects all users; be careful.
