function Invoke-EntraComplianceCheck {
    <#
    .SYNOPSIS
        Entry point for running a full Entra ID compliance audit.
    .DESCRIPTION
        Optionally connects to Microsoft Graph, executes selected compliance checks,
        and returns a structured report.  The report can also be saved to disk as
        JSON or CSV.
    .PARAMETER TenantId
        Optional. The Entra ID tenant to connect to (used with -Connect).
    .PARAMETER RulesPath
        Optional. Path to a custom compliance-rules.yaml configuration file.
    .PARAMETER CheckNames
        One or more check categories to run.  Defaults to 'All'.
        Valid values: SecurityDefaults, ConditionalAccess, MFAPolicy, PasswordPolicy, All
    .PARAMETER OutputPath
        Optional. File path where the report should be saved.
    .PARAMETER OutputFormat
        Format for the saved report file.  Defaults to 'None' (no file written).
        Valid values: JSON, CSV, None
    .PARAMETER Connect
        When specified, the function connects to Microsoft Graph before running checks.
    .OUTPUTS
        PSCustomObject  (type name: EntraComplianceAuditor.ComplianceReport)
    .EXAMPLE
        Invoke-EntraComplianceCheck -Connect
    .EXAMPLE
        Invoke-EntraComplianceCheck -Connect -TenantId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' `
            -OutputPath './report.json' -OutputFormat JSON
    .EXAMPLE
        Invoke-EntraComplianceCheck -CheckNames SecurityDefaults, ConditionalAccess
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [string]$TenantId,

        [string]$RulesPath,

        [ValidateSet('SecurityDefaults', 'ConditionalAccess', 'MFAPolicy', 'PasswordPolicy', 'All')]
        [string[]]$CheckNames = @('All'),

        [string]$OutputPath,

        [ValidateSet('JSON', 'CSV', 'None')]
        [string]$OutputFormat = 'None',

        [switch]$Connect
    )

    if ($Connect) {
        $connectParams = @{}
        if ($TenantId) { $connectParams['TenantId'] = $TenantId }
        Connect-EntraService @connectParams
    }

    $reportParams = @{ CheckNames = $CheckNames }
    if ($RulesPath) { $reportParams['RulesPath'] = $RulesPath }

    $report = Get-EntraComplianceReport @reportParams

    if ($OutputPath -and $OutputFormat -ne 'None') {
        switch ($OutputFormat) {
            'JSON' {
                $report | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding UTF8
                Write-Verbose "Report saved to '$OutputPath' (JSON)."
            }
            'CSV' {
                $report.Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
                Write-Verbose "Report saved to '$OutputPath' (CSV)."
            }
        }
    }

    return $report
}
