function New-ComplianceResult {
    <#
    .SYNOPSIS
        Creates a standardised compliance-check result object.
    .OUTPUTS
        PSCustomObject  (type name: EntraComplianceAuditor.ComplianceResult)
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory)]
        [string]$CheckName,

        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Fail', 'Warning', 'NotApplicable', 'Error')]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Description,

        [string]$Recommendation = '',

        [object]$Details = $null,

        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')]
        [string]$Severity = 'Medium'
    )

    [PSCustomObject]@{
        PSTypeName     = 'EntraComplianceAuditor.ComplianceResult'
        CheckName      = $CheckName
        Category       = $Category
        Status         = $Status
        Description    = $Description
        Recommendation = $Recommendation
        Details        = $Details
        Severity       = $Severity
        Timestamp      = (Get-Date -Format 'o')
    }
}
