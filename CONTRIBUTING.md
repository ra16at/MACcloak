Contributing to MACcloak
=======================

Thanks for wanting to contribute! Small, focused pull requests are preferred.

Steps to contribute

1. Fork the repository and create a feature branch.
2. Run tests and linters locally:

```powershell
# Validate config (adjust path if you installed to Program Files)
pwsh .\test-validate-config.ps1

# Run script analyzer
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force
Invoke-ScriptAnalyzer -Path .\RandomMAC.ps1 -Recurse
```

3. Keep changes minimal and document security-related changes clearly.
4. Open a pull request and include a short description of the change and why it's safe.

Maintainer notes
- CI will check PSScriptAnalyzer and validate config. The signature check is a warning to avoid blocking development before a signed release.
- For releases, sign `RandomMAC.ps1` and update CI to enforce the signature.
