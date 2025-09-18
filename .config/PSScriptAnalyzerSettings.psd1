@{
    # Use built-in rules but tune severities and excludes
    IncludeRules = @(
        'PSAvoidDefaultValueSwitchParameter',
        'PSAvoidGlobalVars',
        'PSAvoidUsingWriteHost',
        'PSUseApprovedVerbs',
        'PSUseConsistentIndentation',
        'PSUseConsistentWhitespace',
        'PSUseDeclaredVarsMoreThanAssignments',
        'PSUseUTF8Encoding'
    )

    ExcludeRules = @(
        # Allow Write-Host for explicit user-facing CLI messages
        'PSAvoidUsingWriteHost'
    )

    Rules = @{
        PSUseConsistentIndentation = @{ IndentationSize = 4; PipelineIndentation = 'IncreaseIndentationForFirstPipeline' }
        PSUseConsistentWhitespace = @{ CheckInnerBrace = $true; CheckOpenBrace = $true; CheckOpenParen = $true; CheckOperator = $true; CheckPipe = $true; CheckSeparator = $true }
        PSUseApprovedVerbs = @{ Enable = $true }
    }
}
