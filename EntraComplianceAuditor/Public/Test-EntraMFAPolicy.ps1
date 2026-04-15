function Test-EntraMFAPolicy {
    <#
    .SYNOPSIS
        Audits the tenant's Authentication Methods policy configuration.
    .PARAMETER Rules
        Optional compliance-rules hashtable. If omitted, defaults are loaded automatically.
    .OUTPUTS
        PSCustomObject[]  (type name: EntraComplianceAuditor.ComplianceResult)
    .EXAMPLE
        Test-EntraMFAPolicy
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param (
        [hashtable]$Rules
    )

    if (-not $Rules) {
        $Rules = Get-ComplianceRules
    }

    $results  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = 'MFA Policy'

    try {
        $authMethodPolicy = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction Stop

        $migrationState   = $authMethodPolicy.PolicyMigrationState

        # Migration states that indicate a properly managed policy
        $validStates = @('migrationComplete', 'preMigration', 'migrationInProgress')

        if ($migrationState -in $validStates) {
            $results.Add((New-ComplianceResult `
                -CheckName   'AuthenticationMethodPolicy' `
                -Category    $category `
                -Status      'Pass' `
                -Description "Authentication methods policy is configured (migration state: '$migrationState')." `
                -Details     @{ PolicyMigrationState = $migrationState } `
                -Severity    'Medium'))
        } else {
            $results.Add((New-ComplianceResult `
                -CheckName      'AuthenticationMethodPolicy' `
                -Category       $category `
                -Status         'Warning' `
                -Description    "Authentication methods policy migration state is '$migrationState'." `
                -Recommendation 'Review and manage authentication methods in the Microsoft Entra admin center under Protection > Authentication methods.' `
                -Details        @{ PolicyMigrationState = $migrationState } `
                -Severity       'Medium'))
        }

    } catch {
        $results.Add((New-ComplianceResult `
            -CheckName   'AuthenticationMethodPolicy' `
            -Category    $category `
            -Status      'Error' `
            -Description "Failed to retrieve authentication methods policy: $_" `
            -Severity    'Medium'))
    }

    return $results.ToArray()
}
