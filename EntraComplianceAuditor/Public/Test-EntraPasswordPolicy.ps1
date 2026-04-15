function Test-EntraPasswordPolicy {
    <#
    .SYNOPSIS
        Audits the organisation's password validity settings.
    .DESCRIPTION
        Checks the password validity period configured at the organisation level
        and compares it against the maximum age defined in the compliance rules.
    .PARAMETER Rules
        Optional compliance-rules hashtable. If omitted, defaults are loaded automatically.
    .OUTPUTS
        PSCustomObject[]  (type name: EntraComplianceAuditor.ComplianceResult)
    .EXAMPLE
        Test-EntraPasswordPolicy
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
    $category = 'Password Policy'

    try {
        $organizations = @(Get-MgOrganization -ErrorAction Stop)

        if ($organizations.Count -eq 0) {
            $results.Add((New-ComplianceResult `
                -CheckName   'PasswordPolicy' `
                -Category    $category `
                -Status      'Warning' `
                -Description 'No organisation object was returned; cannot assess password policy.' `
                -Severity    'Low'))
            return $results.ToArray()
        }

        $org = $organizations[0]
        $validityPeriod = $org.PasswordValidityPeriodInDays

        # Int32.MaxValue (2147483647) is the Graph API sentinel for "never expires"
        if ($validityPeriod -eq [int]::MaxValue -or $null -eq $validityPeriod) {
            $results.Add((New-ComplianceResult `
                -CheckName      'PasswordExpiry' `
                -Category       $category `
                -Status         'Warning' `
                -Description    'Cloud-managed passwords are set to never expire.' `
                -Recommendation 'Consider enforcing password expiry or ensure phishing-resistant MFA is required for all users.' `
                -Details        @{ PasswordValidityPeriodInDays = $validityPeriod } `
                -Severity       'Low'))
        } elseif ($validityPeriod -le $Rules.PasswordPolicy.MaxPasswordAgeDays) {
            $results.Add((New-ComplianceResult `
                -CheckName   'PasswordExpiry' `
                -Category    $category `
                -Status      'Pass' `
                -Description "Password validity period is $validityPeriod days, within the required $($Rules.PasswordPolicy.MaxPasswordAgeDays)-day maximum." `
                -Details     @{ PasswordValidityPeriodInDays = $validityPeriod } `
                -Severity    'Low'))
        } else {
            $results.Add((New-ComplianceResult `
                -CheckName      'PasswordExpiry' `
                -Category       $category `
                -Status         'Fail' `
                -Description    "Password validity period ($validityPeriod days) exceeds the required maximum of $($Rules.PasswordPolicy.MaxPasswordAgeDays) days." `
                -Recommendation "Reduce the password validity period to $($Rules.PasswordPolicy.MaxPasswordAgeDays) days or fewer." `
                -Details        @{ PasswordValidityPeriodInDays = $validityPeriod } `
                -Severity       'Medium'))
        }

    } catch {
        $results.Add((New-ComplianceResult `
            -CheckName   'PasswordPolicy' `
            -Category    $category `
            -Status      'Error' `
            -Description "Failed to retrieve password policy: $_" `
            -Severity    'Medium'))
    }

    return $results.ToArray()
}
