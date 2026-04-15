function Test-EntraSecurityDefaults {
    <#
    .SYNOPSIS
        Checks whether Microsoft Entra ID Security Defaults are enabled.
    .PARAMETER Rules
        Optional compliance-rules hashtable. If omitted, defaults are loaded automatically.
    .OUTPUTS
        PSCustomObject  (type name: EntraComplianceAuditor.ComplianceResult)
    .EXAMPLE
        Test-EntraSecurityDefaults
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [hashtable]$Rules
    )

    if (-not $Rules) {
        $Rules = Get-ComplianceRules
    }

    $checkName = 'SecurityDefaults'
    $category  = 'Identity Protection'

    try {
        $policy = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop

        if ($policy.IsEnabled) {
            return New-ComplianceResult `
                -CheckName   $checkName `
                -Category    $category `
                -Status      'Pass' `
                -Description 'Security defaults are enabled, providing baseline identity protection.' `
                -Severity    'High'
        } else {
            return New-ComplianceResult `
                -CheckName      $checkName `
                -Category       $category `
                -Status         'Fail' `
                -Description    'Security defaults are disabled. Ensure Conditional Access policies provide equivalent protection.' `
                -Recommendation 'Enable security defaults or configure equivalent Conditional Access policies covering MFA and legacy-auth blocking.' `
                -Severity       'High'
        }
    } catch {
        return New-ComplianceResult `
            -CheckName   $checkName `
            -Category    $category `
            -Status      'Error' `
            -Description "Failed to retrieve security defaults policy: $_" `
            -Severity    'High'
    }
}
