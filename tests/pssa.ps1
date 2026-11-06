param([string]$Path, [string]$PssaDir)
Import-Module (Join-Path $PssaDir 'PSScriptAnalyzer.psd1') -Force
$profiles = @('win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework', 'win-8_x64_10.0.14393.0_5.1.14393.2791_x64_4.0.30319.42000_framework')
$settings = @{
    Rules = @{
        PSUseCompatibleSyntax   = @{ Enable = $true; TargetVersions = @('5.1') }
        PSUseCompatibleCommands = @{ Enable = $true; TargetProfiles = $profiles }
        PSUseCompatibleTypes    = @{ Enable = $true; TargetProfiles = $profiles }
    }
    IncludeRules = @('PSUseCompatibleSyntax', 'PSUseCompatibleCommands', 'PSUseCompatibleTypes',
        'PSAvoidUsingCmdletAliases', 'PSUseDeclaredVarsMoreThanAssignments', 'PSAvoidAssignmentToAutomaticVariable',
        'PSPossibleIncorrectComparisonWithNull', 'PSAvoidUsingEmptyCatchBlock', 'PSMisleadingBacktick', 'PSAvoidUsingInvokeExpression',
        'PSAvoidGlobalVars', 'PSUseApprovedVerbs', 'PSAvoidDefaultValueSwitchParameter', 'PSReservedCmdletChar', 'PSPossibleIncorrectUsageOfAssignmentOperator')
}
$r = Invoke-ScriptAnalyzer -Path $Path -Settings $settings
$r | Group-Object RuleName | Sort-Object Count -Descending | ForEach-Object { '{0,5}  {1}' -f $_.Count, $_.Name }
''
$r | Where-Object { $_.RuleName -like 'PSUseCompatible*' -or $_.RuleName -in 'PSAvoidAssignmentToAutomaticVariable', 'PSPossibleIncorrectUsageOfAssignmentOperator', 'PSMisleadingBacktick', 'PSUseDeclaredVarsMoreThanAssignments', 'PSAvoidUsingCmdletAliases' } |
    ForEach-Object { '{0}:{1} {2} {3}' -f $_.Line, $_.Column, $_.RuleName, $_.Message }
