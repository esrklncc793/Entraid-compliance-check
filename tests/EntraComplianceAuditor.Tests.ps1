#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    # ---------------------------------------------------------------------------
    # Stub external dependencies that may not be available in CI
    # ---------------------------------------------------------------------------

    # powershell-yaml may not be installed; provide a minimal stub so
    # Get-ComplianceRules falls back to built-in defaults gracefully.
    if (-not (Get-Command -Name ConvertFrom-Yaml -ErrorAction SilentlyContinue)) {
        function global:ConvertFrom-Yaml {
            param([string]$InputObject)
            return $null   # triggers the 'fall back to defaults' branch
        }
    }

    # Stub Microsoft Graph cmdlets so the module loads without Microsoft.Graph installed.
    function global:Get-MgContext {
        [PSCustomObject]@{ TenantId = '00000000-0000-0000-0000-000000000001' }
    }
    function global:Connect-MgGraph { }
    function global:Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy {
        [PSCustomObject]@{ IsEnabled = $true }
    }
    function global:Get-MgIdentityConditionalAccessPolicy { return @() }
    function global:Get-MgPolicyAuthenticationMethodPolicy {
        [PSCustomObject]@{ PolicyMigrationState = 'migrationComplete' }
    }
    function global:Get-MgDomain {
        @([PSCustomObject]@{ Id = 'test.onmicrosoft.com'; IsDefault = $true })
    }
    function global:Get-MgOrganization {
        @([PSCustomObject]@{
            PasswordNotificationDays     = 14
            PasswordValidityPeriodInDays = 90
        })
    }

    # ---------------------------------------------------------------------------
    # Import the module
    # ---------------------------------------------------------------------------
    $modulePsd1 = Join-Path $PSScriptRoot '../EntraComplianceAuditor/EntraComplianceAuditor.psd1'
    Import-Module $modulePsd1 -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name EntraComplianceAuditor -ErrorAction SilentlyContinue
}

# =============================================================================
Describe 'Module: EntraComplianceAuditor' {

    Context 'Import' {
        It 'loads without errors' {
            Get-Module -Name EntraComplianceAuditor | Should -Not -BeNullOrEmpty
        }

        It 'exports the expected public functions' {
            $exported = (Get-Module -Name EntraComplianceAuditor).ExportedFunctions.Keys
            $exported | Should -Contain 'Invoke-EntraComplianceCheck'
            $exported | Should -Contain 'Get-EntraComplianceReport'
            $exported | Should -Contain 'Test-EntraConditionalAccess'
            $exported | Should -Contain 'Test-EntraMFAPolicy'
            $exported | Should -Contain 'Test-EntraPasswordPolicy'
            $exported | Should -Contain 'Test-EntraSecurityDefaults'
        }

        It 'does not export private functions' {
            $exported = (Get-Module -Name EntraComplianceAuditor).ExportedFunctions.Keys
            $exported | Should -Not -Contain 'New-ComplianceResult'
            $exported | Should -Not -Contain 'Get-ComplianceRules'
            $exported | Should -Not -Contain 'Connect-EntraService'
        }
    }
}

# =============================================================================
Describe 'Test-EntraSecurityDefaults' {

    Context 'Security defaults enabled' {
        BeforeEach {
            Mock Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy {
                [PSCustomObject]@{ IsEnabled = $true }
            } -ModuleName EntraComplianceAuditor
        }

        It 'returns a Pass result' {
            $result = Test-EntraSecurityDefaults
            $result.Status | Should -Be 'Pass'
        }

        It 'has the correct CheckName' {
            $result = Test-EntraSecurityDefaults
            $result.CheckName | Should -Be 'SecurityDefaults'
        }

        It 'has the correct Category' {
            $result = Test-EntraSecurityDefaults
            $result.Category | Should -Be 'Identity Protection'
        }

        It 'reports High severity' {
            $result = Test-EntraSecurityDefaults
            $result.Severity | Should -Be 'High'
        }
    }

    Context 'Security defaults disabled' {
        BeforeEach {
            Mock Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy {
                [PSCustomObject]@{ IsEnabled = $false }
            } -ModuleName EntraComplianceAuditor
        }

        It 'returns a Fail result' {
            $result = Test-EntraSecurityDefaults
            $result.Status | Should -Be 'Fail'
        }

        It 'includes a non-empty Recommendation' {
            $result = Test-EntraSecurityDefaults
            $result.Recommendation | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Graph API unavailable' {
        BeforeEach {
            Mock Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy {
                throw 'Simulated Graph error'
            } -ModuleName EntraComplianceAuditor
        }

        It 'returns an Error result instead of throwing' {
            { $result = Test-EntraSecurityDefaults } | Should -Not -Throw
            $result = Test-EntraSecurityDefaults
            $result.Status | Should -Be 'Error'
        }
    }
}

# =============================================================================
Describe 'Test-EntraConditionalAccess' {

    Context 'No Conditional Access policies exist' {
        BeforeEach {
            Mock Get-MgIdentityConditionalAccessPolicy { return @() } `
                -ModuleName EntraComplianceAuditor
        }

        It 'returns at least one result' {
            $results = Test-EntraConditionalAccess
            $results.Count | Should -BeGreaterThan 0
        }

        It 'returns a Fail for BlockLegacyAuthentication' {
            $results = Test-EntraConditionalAccess
            $block = $results | Where-Object { $_.CheckName -eq 'BlockLegacyAuthentication' }
            $block.Status | Should -Be 'Fail'
        }

        It 'returns a Fail for RequireMFAForAdmins' {
            $results = Test-EntraConditionalAccess
            $mfa = $results | Where-Object { $_.CheckName -eq 'RequireMFAForAdmins' }
            $mfa.Status | Should -Be 'Fail'
        }
    }

    Context 'Policies exist that block legacy auth and require admin MFA' {
        BeforeEach {
            Mock Get-MgIdentityConditionalAccessPolicy {
                @(
                    [PSCustomObject]@{
                        State          = 'enabled'
                        Conditions     = [PSCustomObject]@{
                            ClientAppTypes = @('exchangeActiveSync', 'other')
                            Users          = [PSCustomObject]@{
                                IncludeUsers = @('All')
                                IncludeRoles = @()
                            }
                        }
                        GrantControls  = [PSCustomObject]@{
                            Operator         = 'OR'
                            BuiltInControls  = @('block')
                        }
                    },
                    [PSCustomObject]@{
                        State          = 'enabled'
                        Conditions     = [PSCustomObject]@{
                            ClientAppTypes = @('browser', 'mobileAppsAndDesktopClients')
                            Users          = [PSCustomObject]@{
                                IncludeUsers = @()
                                IncludeRoles = @('62e90394-69f5-4237-9190-012177145e10') # Global Admin
                            }
                        }
                        GrantControls  = [PSCustomObject]@{
                            Operator        = 'OR'
                            BuiltInControls = @('mfa')
                        }
                    }
                )
            } -ModuleName EntraComplianceAuditor
        }

        It 'returns Pass for BlockLegacyAuthentication' {
            $results = Test-EntraConditionalAccess
            $block = $results | Where-Object { $_.CheckName -eq 'BlockLegacyAuthentication' }
            $block.Status | Should -Be 'Pass'
        }

        It 'returns Pass for RequireMFAForAdmins' {
            $results = Test-EntraConditionalAccess
            $mfa = $results | Where-Object { $_.CheckName -eq 'RequireMFAForAdmins' }
            $mfa.Status | Should -Be 'Pass'
        }
    }

    Context 'Graph API unavailable' {
        BeforeEach {
            Mock Get-MgIdentityConditionalAccessPolicy {
                throw 'Simulated Graph error'
            } -ModuleName EntraComplianceAuditor
        }

        It 'returns an Error result instead of throwing' {
            { $results = Test-EntraConditionalAccess } | Should -Not -Throw
            $results = Test-EntraConditionalAccess
            ($results | Where-Object { $_.Status -eq 'Error' }).Count | Should -BeGreaterThan 0
        }
    }
}

# =============================================================================
Describe 'Test-EntraMFAPolicy' {

    Context 'Policy migration is complete' {
        BeforeEach {
            Mock Get-MgPolicyAuthenticationMethodPolicy {
                [PSCustomObject]@{ PolicyMigrationState = 'migrationComplete' }
            } -ModuleName EntraComplianceAuditor
        }

        It 'returns a Pass result' {
            $results = Test-EntraMFAPolicy
            $results[0].Status | Should -Be 'Pass'
        }
    }

    Context 'Policy migration state is unknown' {
        BeforeEach {
            Mock Get-MgPolicyAuthenticationMethodPolicy {
                [PSCustomObject]@{ PolicyMigrationState = 'unknownFutureValue' }
            } -ModuleName EntraComplianceAuditor
        }

        It 'returns a Warning result' {
            $results = Test-EntraMFAPolicy
            $results[0].Status | Should -Be 'Warning'
        }

        It 'includes a Recommendation' {
            $results = Test-EntraMFAPolicy
            $results[0].Recommendation | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Graph API unavailable' {
        BeforeEach {
            Mock Get-MgPolicyAuthenticationMethodPolicy {
                throw 'Simulated Graph error'
            } -ModuleName EntraComplianceAuditor
        }

        It 'returns an Error result instead of throwing' {
            { $results = Test-EntraMFAPolicy } | Should -Not -Throw
            $results = Test-EntraMFAPolicy
            $results[0].Status | Should -Be 'Error'
        }
    }
}

# =============================================================================
Describe 'Test-EntraPasswordPolicy' {

    Context 'Password validity within policy' {
        BeforeEach {
            Mock Get-MgOrganization {
                @([PSCustomObject]@{ PasswordValidityPeriodInDays = 90 })
            } -ModuleName EntraComplianceAuditor
        }

        It 'returns a Pass result' {
            $results = Test-EntraPasswordPolicy
            ($results | Where-Object { $_.CheckName -eq 'PasswordExpiry' }).Status | Should -Be 'Pass'
        }
    }

    Context 'Password validity exceeds policy maximum' {
        BeforeEach {
            Mock Get-MgOrganization {
                @([PSCustomObject]@{ PasswordValidityPeriodInDays = 365 })
            } -ModuleName EntraComplianceAuditor
        }

        It 'returns a Fail result' {
            $results = Test-EntraPasswordPolicy
            ($results | Where-Object { $_.CheckName -eq 'PasswordExpiry' }).Status | Should -Be 'Fail'
        }
    }

    Context 'Passwords never expire (sentinel value)' {
        BeforeEach {
            Mock Get-MgOrganization {
                @([PSCustomObject]@{ PasswordValidityPeriodInDays = [int]::MaxValue })
            } -ModuleName EntraComplianceAuditor
        }

        It 'returns a Warning result' {
            $results = Test-EntraPasswordPolicy
            ($results | Where-Object { $_.CheckName -eq 'PasswordExpiry' }).Status | Should -Be 'Warning'
        }
    }

    Context 'Graph API unavailable' {
        BeforeEach {
            Mock Get-MgOrganization {
                throw 'Simulated Graph error'
            } -ModuleName EntraComplianceAuditor
        }

        It 'returns an Error result instead of throwing' {
            { $results = Test-EntraPasswordPolicy } | Should -Not -Throw
            $results = Test-EntraPasswordPolicy
            ($results | Where-Object { $_.Status -eq 'Error' }).Count | Should -BeGreaterThan 0
        }
    }
}

# =============================================================================
Describe 'Get-EntraComplianceReport' {

    BeforeAll {
        Mock Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy {
            [PSCustomObject]@{ IsEnabled = $true }
        } -ModuleName EntraComplianceAuditor

        Mock Get-MgIdentityConditionalAccessPolicy { return @() } `
            -ModuleName EntraComplianceAuditor

        Mock Get-MgPolicyAuthenticationMethodPolicy {
            [PSCustomObject]@{ PolicyMigrationState = 'migrationComplete' }
        } -ModuleName EntraComplianceAuditor

        Mock Get-MgOrganization {
            @([PSCustomObject]@{ PasswordValidityPeriodInDays = 90 })
        } -ModuleName EntraComplianceAuditor

        Mock Get-MgContext {
            [PSCustomObject]@{ TenantId = '00000000-0000-0000-0000-000000000001' }
        } -ModuleName EntraComplianceAuditor
    }

    It 'returns a report object with a Results array' {
        $report = Get-EntraComplianceReport
        $report | Should -Not -BeNullOrEmpty
        $report.Results | Should -Not -BeNullOrEmpty
    }

    It 'includes a Summary with Total, Pass, Fail, Warning, Error counts' {
        $report = Get-EntraComplianceReport
        $report.Summary.Total   | Should -BeGreaterThan 0
        $report.Summary.Pass    | Should -BeGreaterOrEqual 0
        $report.Summary.Fail    | Should -BeGreaterOrEqual 0
        $report.Summary.Warning | Should -BeGreaterOrEqual 0
        $report.Summary.Error   | Should -BeGreaterOrEqual 0
    }

    It 'has a ComplianceScore between 0 and 100' {
        $report = Get-EntraComplianceReport
        $report.ComplianceScore | Should -BeGreaterOrEqual 0
        $report.ComplianceScore | Should -BeLessOrEqual 100
    }

    It 'includes the TenantId from Get-MgContext' {
        $report = Get-EntraComplianceReport
        $report.TenantId | Should -Be '00000000-0000-0000-0000-000000000001'
    }

    It 'runs only the requested check when CheckNames is specified' {
        $report = Get-EntraComplianceReport -CheckNames SecurityDefaults
        $report.Results | ForEach-Object {
            $_.Category | Should -Be 'Identity Protection'
        }
    }
}

# =============================================================================
Describe 'Invoke-EntraComplianceCheck' {

    BeforeAll {
        Mock Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy {
            [PSCustomObject]@{ IsEnabled = $true }
        } -ModuleName EntraComplianceAuditor

        Mock Get-MgIdentityConditionalAccessPolicy { return @() } `
            -ModuleName EntraComplianceAuditor

        Mock Get-MgPolicyAuthenticationMethodPolicy {
            [PSCustomObject]@{ PolicyMigrationState = 'migrationComplete' }
        } -ModuleName EntraComplianceAuditor

        Mock Get-MgOrganization {
            @([PSCustomObject]@{ PasswordValidityPeriodInDays = 90 })
        } -ModuleName EntraComplianceAuditor

        Mock Get-MgContext {
            [PSCustomObject]@{ TenantId = '00000000-0000-0000-0000-000000000001' }
        } -ModuleName EntraComplianceAuditor
    }

    It 'returns a compliance report without -Connect' {
        $report = Invoke-EntraComplianceCheck
        $report | Should -Not -BeNullOrEmpty
        $report.Results | Should -Not -BeNullOrEmpty
    }

    It 'saves a JSON file when -OutputFormat JSON and -OutputPath are provided' {
        $tmpFile = Join-Path $TestDrive 'report.json'
        Invoke-EntraComplianceCheck -OutputPath $tmpFile -OutputFormat JSON
        $tmpFile | Should -Exist
        $content = Get-Content $tmpFile -Raw | ConvertFrom-Json
        $content.ComplianceScore | Should -BeGreaterOrEqual 0
    }

    It 'saves a CSV file when -OutputFormat CSV and -OutputPath are provided' {
        $tmpFile = Join-Path $TestDrive 'report.csv'
        Invoke-EntraComplianceCheck -OutputPath $tmpFile -OutputFormat CSV
        $tmpFile | Should -Exist
    }
}
