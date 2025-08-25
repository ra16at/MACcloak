@{
    # Minimal PSScriptAnalyzer settings for this project.
    # We intentionally allow Write-Host in scripts used for interactive messaging.
    Rules = @{
        PSAvoidUsingWriteHost = @{ Enable = $false }
    }
}
