@{
    RootModule        = 'EntraComplianceAuditor.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '0ca2a1b3-bc10-429f-afee-9295ba01239e'
    Author            = 'Entra ID Compliance Team'
    CompanyName       = 'Unknown'
    Copyright         = '(c) 2024. All rights reserved.'
    Description       = 'Audits Microsoft Entra ID (Azure AD) tenant settings against configurable compliance rules.'
    PowerShellVersion = '5.1'

    # Microsoft.Graph sub-modules are required at runtime but not declared here
    # so the module can still load for offline testing and rule inspection.
    # Install-Module Microsoft.Graph before running live checks.

    FunctionsToExport = @(
        'Invoke-EntraComplianceCheck',
        'Get-EntraComplianceReport',
        'Test-EntraConditionalAccess',
        'Test-EntraMFAPolicy',
        'Test-EntraPasswordPolicy',
        'Test-EntraSecurityDefaults'
    )

    CmdletsToExport   = @()
    AliasesToExport   = @()
    VariablesToExport = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('Entra', 'AzureAD', 'Compliance', 'Security', 'Audit', 'MFA', 'ConditionalAccess')
            ProjectUri   = 'https://github.com/esrklncc793/Entraid-compliance-check'
            ReleaseNotes = 'Initial release.'
        }
    }
}
