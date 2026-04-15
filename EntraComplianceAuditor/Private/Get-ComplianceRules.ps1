function Get-ComplianceRules {
    <#
    .SYNOPSIS
        Loads compliance rules from a YAML file, falling back to built-in defaults.
    .PARAMETER RulesPath
        Path to the compliance-rules.yaml file.
        Defaults to the config/ directory bundled with the module.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [string]$RulesPath = (Join-Path $PSScriptRoot '../config/compliance-rules.yaml')
    )

    # Built-in defaults – used when no YAML file is present or readable
    $defaults = @{
        ConditionalAccess = @{
            BlockLegacyAuthentication = $true
            RequireMFAForAdmins       = $true
            RequireMFAForAllUsers     = $false
            RequireCompliantDevice    = $false
        }
        MFAPolicy         = @{
            RequireAdminMFA = $true
            RequireUserMFA  = $false
        }
        PasswordPolicy    = @{
            MaxPasswordAgeDays             = 90
            MinPasswordLength              = 8
            EnableSelfServicePasswordReset = $true
        }
        SecurityDefaults  = @{
            RequireSecurityDefaultsOrCA = $true
        }
    }

    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($RulesPath)
    if (Test-Path -Path $resolvedPath -PathType Leaf) {
        try {
            $content = Get-Content -Path $resolvedPath -Raw -ErrorAction Stop
            $loaded  = ConvertFrom-Yaml -InputObject $content
            if ($null -ne $loaded) {
                return $loaded
            }
        } catch {
            Write-Warning "Could not load compliance rules from '$resolvedPath'. Using built-in defaults. Error: $_"
        }
    }

    return $defaults
}
