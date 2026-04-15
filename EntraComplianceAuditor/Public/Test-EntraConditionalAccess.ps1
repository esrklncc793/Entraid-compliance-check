function Test-EntraConditionalAccess {
    <#
    .SYNOPSIS
        Audits Conditional Access policies for key security controls.
    .DESCRIPTION
        Checks for policies that:
          - Block legacy authentication protocols
          - Require MFA for administrative roles
          - Require MFA for all users (optional, controlled by rules)
    .PARAMETER Rules
        Optional compliance-rules hashtable. If omitted, defaults are loaded automatically.
    .OUTPUTS
        PSCustomObject[]  (type name: EntraComplianceAuditor.ComplianceResult)
    .EXAMPLE
        Test-EntraConditionalAccess
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
    $category = 'Conditional Access'

    try {
        $policies        = Get-MgIdentityConditionalAccessPolicy -ErrorAction Stop
        $enabledPolicies = @($policies | Where-Object { $_.State -eq 'enabled' })

        # --- Check: Legacy authentication blocked ---
        if ($Rules.ConditionalAccess.BlockLegacyAuthentication) {
            $legacyAuthPolicy = $enabledPolicies | Where-Object {
                $clientTypes = $_.Conditions.ClientAppTypes
                ($clientTypes -contains 'exchangeActiveSync' -or $clientTypes -contains 'other') -and
                ($_.GrantControls.Operator -eq 'OR' -or $_.GrantControls.Operator -eq 'AND') -and
                ($_.GrantControls.BuiltInControls -contains 'block')
            }

            if ($legacyAuthPolicy) {
                $results.Add((New-ComplianceResult `
                    -CheckName   'BlockLegacyAuthentication' `
                    -Category    $category `
                    -Status      'Pass' `
                    -Description 'A Conditional Access policy blocks legacy authentication protocols.' `
                    -Severity    'Critical'))
            } else {
                $results.Add((New-ComplianceResult `
                    -CheckName      'BlockLegacyAuthentication' `
                    -Category       $category `
                    -Status         'Fail' `
                    -Description    'No enabled Conditional Access policy was found that blocks legacy authentication.' `
                    -Recommendation 'Create a Conditional Access policy targeting all users with legacy auth client apps and set Grant to Block.' `
                    -Severity       'Critical'))
            }
        }

        # --- Check: MFA required for admins ---
        if ($Rules.ConditionalAccess.RequireMFAForAdmins) {
            $adminMFAPolicy = $enabledPolicies | Where-Object {
                ($_.Conditions.Users.IncludeRoles.Count -gt 0) -and
                ($_.GrantControls.BuiltInControls -contains 'mfa')
            }

            if ($adminMFAPolicy) {
                $results.Add((New-ComplianceResult `
                    -CheckName   'RequireMFAForAdmins' `
                    -Category    $category `
                    -Status      'Pass' `
                    -Description 'A Conditional Access policy requires MFA for administrative roles.' `
                    -Severity    'Critical'))
            } else {
                $results.Add((New-ComplianceResult `
                    -CheckName      'RequireMFAForAdmins' `
                    -Category       $category `
                    -Status         'Fail' `
                    -Description    'No enabled Conditional Access policy requires MFA for administrative roles.' `
                    -Recommendation 'Create a Conditional Access policy targeting all admin roles and require MFA as the grant control.' `
                    -Severity       'Critical'))
            }
        }

        # --- Check: MFA required for all users (optional) ---
        if ($Rules.ConditionalAccess.RequireMFAForAllUsers) {
            $allUserMFAPolicy = $enabledPolicies | Where-Object {
                ($_.Conditions.Users.IncludeUsers -contains 'All') -and
                ($_.GrantControls.BuiltInControls -contains 'mfa')
            }

            if ($allUserMFAPolicy) {
                $results.Add((New-ComplianceResult `
                    -CheckName   'RequireMFAForAllUsers' `
                    -Category    $category `
                    -Status      'Pass' `
                    -Description 'A Conditional Access policy requires MFA for all users.' `
                    -Severity    'High'))
            } else {
                $results.Add((New-ComplianceResult `
                    -CheckName      'RequireMFAForAllUsers' `
                    -Category       $category `
                    -Status         'Fail' `
                    -Description    'No enabled Conditional Access policy requires MFA for all users.' `
                    -Recommendation 'Create a Conditional Access policy targeting all users and require MFA as the grant control.' `
                    -Severity       'High'))
            }
        }

    } catch {
        $results.Add((New-ComplianceResult `
            -CheckName   'ConditionalAccess' `
            -Category    $category `
            -Status      'Error' `
            -Description "Failed to retrieve Conditional Access policies: $_" `
            -Severity    'Critical'))
    }

    return $results.ToArray()
}
