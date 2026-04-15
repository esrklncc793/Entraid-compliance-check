function Get-EntraComplianceReport {
    <#
    .SYNOPSIS
        Runs selected compliance checks and returns an aggregated report object.
    .PARAMETER RulesPath
        Optional path to a custom compliance-rules.yaml file.
    .PARAMETER CheckNames
        One or more check categories to run.  Defaults to 'All'.
        Valid values: SecurityDefaults, ConditionalAccess, MFAPolicy, PasswordPolicy, All
    .OUTPUTS
        PSCustomObject  (type name: EntraComplianceAuditor.ComplianceReport)
    .EXAMPLE
        Get-EntraComplianceReport
    .EXAMPLE
        Get-EntraComplianceReport -CheckNames SecurityDefaults, ConditionalAccess
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [string]$RulesPath,

        [ValidateSet('SecurityDefaults', 'ConditionalAccess', 'MFAPolicy', 'PasswordPolicy', 'All')]
        [string[]]$CheckNames = @('All')
    )

    $rulesParams = @{}
    if ($RulesPath) { $rulesParams['RulesPath'] = $RulesPath }
    $rules = Get-ComplianceRules @rulesParams

    $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $runAll     = $CheckNames -contains 'All'

    if ($runAll -or $CheckNames -contains 'SecurityDefaults') {
        $allResults.Add((Test-EntraSecurityDefaults -Rules $rules))
    }

    if ($runAll -or $CheckNames -contains 'ConditionalAccess') {
        Test-EntraConditionalAccess -Rules $rules | ForEach-Object { $allResults.Add($_) }
    }

    if ($runAll -or $CheckNames -contains 'MFAPolicy') {
        Test-EntraMFAPolicy -Rules $rules | ForEach-Object { $allResults.Add($_) }
    }

    if ($runAll -or $CheckNames -contains 'PasswordPolicy') {
        Test-EntraPasswordPolicy -Rules $rules | ForEach-Object { $allResults.Add($_) }
    }

    $passCount    = @($allResults | Where-Object { $_.Status -eq 'Pass'    }).Count
    $failCount    = @($allResults | Where-Object { $_.Status -eq 'Fail'    }).Count
    $warningCount = @($allResults | Where-Object { $_.Status -eq 'Warning' }).Count
    $errorCount   = @($allResults | Where-Object { $_.Status -eq 'Error'   }).Count
    $totalCount   = $allResults.Count

    $complianceScore = if ($totalCount -gt 0) {
        [math]::Round(($passCount / $totalCount) * 100, 1)
    } else { 0 }

    $tenantId = try { (Get-MgContext).TenantId } catch { 'Unknown' }

    [PSCustomObject]@{
        PSTypeName      = 'EntraComplianceAuditor.ComplianceReport'
        GeneratedAt     = (Get-Date -Format 'o')
        TenantId        = $tenantId
        ComplianceScore = $complianceScore
        Summary         = [PSCustomObject]@{
            Total   = $totalCount
            Pass    = $passCount
            Fail    = $failCount
            Warning = $warningCount
            Error   = $errorCount
        }
        Results         = $allResults.ToArray()
    }
}
