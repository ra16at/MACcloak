Release checklist — MACcloak
===========================

Follow this checklist before pushing a release tag (e.g., v1.0.0).

1) Sanity & tests
- [ ] Run `pwsh .\test-validate-config.ps1` locally (no errors).
- [ ] Run PSScriptAnalyzer: `Invoke-ScriptAnalyzer -Path .\RandomMAC.ps1 -Recurse` and address any Errors.

2) Documentation
- [ ] Update `README.md` and `CHANGELOG` (or commit messages) describing user-facing changes.
- [ ] Confirm `SIGNING.md` and `SECURITY.md` are up to date.

3) Signing
- [ ] Ensure `SIGNING_PFX` and `SIGNING_PFX_PASSWORD` secrets are present in GitHub repository Settings → Secrets → Actions.
- [ ] If you need to rotate keys, export new PFX and replace secrets before releasing.

4) Versioning
- [ ] Update any internal version numbers if present.
- [ ] Create an annotated tag: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`

5) Release (push tag)
- [ ] Push tag: `git push origin vX.Y.Z`.
- [ ] The `release-and-sign.yml` workflow will sign `RandomMAC.ps1`, create a Release, and attach signed assets.

6) Post-release
- [ ] Verify the Release page, download `RandomMAC-<tag>.ps1` and `randommac_pub.cer` and validate signature:

```powershell
Get-AuthenticodeSignature -FilePath RandomMAC-<tag>.ps1 | Format-List *
```

- [ ] Announce release and share verification instructions.

Notes
- Do NOT add `.pfx` files to the repository. Use repository Secrets for signing PFX only.
- For high-value distribution, use a CA-issued code-signing certificate instead of a self-signed PFX.
