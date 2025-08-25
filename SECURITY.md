Security guidance
=================

Never commit private keys or PFX files to version control. PFX files contain private keys that can be used to sign code and impersonate the publisher.

Recommended practice
- Keep signing keys off the repository.
- If you need CI signing, store the PFX in repository secrets (GitHub Actions) and decrypt at runtime.
- Add `*.pfx` to `.gitignore` (already done).

If you want, I can add a sample GitHub Actions signing step that reads a PFX from secrets and uses it to sign during release — but that requires you to securely upload the PFX to repository secrets first.

How to create a GitHub secret for a PFX
--------------------------------------

1. Export the PFX from your Windows machine (the PFX contains the private key):

```powershell
$pw = Read-Host -AsSecureString "Export PFX password"
Export-PfxCertificate -Cert $cert -FilePath .\randommac_signer.pfx -Password $pw
```

2. Base64-encode the PFX so it can be stored in a secret safely:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes('.\randommac_signer.pfx')) > pfx.b64.txt
```

3. Copy the contents of `pfx.b64.txt` and add it as the repository secret `SIGNING_PFX` in GitHub (Settings → Secrets → Actions). Add the PFX password as `SIGNING_PFX_PASSWORD`.

4. The `signing-release.yml` workflow will read these secrets, decode the PFX at runtime, import it into the runner, sign `RandomMAC.ps1`, and clean up.
