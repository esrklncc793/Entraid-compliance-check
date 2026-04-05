#Requires -Version 5.1
<#
.SYNOPSIS
    Pester test suite for the Entra ID Compliance Auditor.

.DESCRIPTION
    Tests the following components:
      - RuleParser.ps1          (ConvertTo-RuleObject, ConvertTo-ConditionObject, Import-ComplianceRules)
      - EntraComplianceAuditor.ps1  (Test-Condition, Test-ObjectAgainstRule)
      - ReportGenerator.ps1     (ConvertTo-HtmlReport, Export-ComplianceReport)

    These tests run entirely without a live Microsoft Graph connection by mocking
    all Mg* commands and module-level functions.

.NOTES
    Run with: Invoke-Pester -Path './tests/EntraComplianceAuditor.Tests.ps1' -Output Detailed
    Requires Pester 5.x:  Install-Module -Name Pester -MinimumVersion 5.0 -Scope CurrentUser -Force
    Requires powershell-yaml: Install-Module -Name powershell-yaml -Scope CurrentUser
#>

BeforeAll {
    # ── Locate module files ──────────────────────────────────────────────────
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $srcRoot  = Join-Path $repoRoot 'src'

    # Stub out the powershell-yaml module so tests work without it installed
    if (-not (Get-Command 'ConvertFrom-Yaml' -ErrorAction SilentlyContinue)) {
        function global:ConvertFrom-Yaml {
            param([string]$Yaml)
            # Minimal stub - real tests that need YAML parsing use a real YAML string below
            throw 'ConvertFrom-Yaml stub: provide real module or use mock'
        }
    }

    # Dot-source modules under test (order matters)
    . (Join-Path $srcRoot 'RuleParser.ps1')
    . (Join-Path $srcRoot 'ReportGenerator.ps1')

    # Dot-source main auditor (suppress the script-level entry point execution)
    # We set $MyInvocation.InvocationName equivalent by dot-sourcing
    . (Join-Path $srcRoot 'EntraComplianceAuditor.ps1')
}

# ═══════════════════════════════════════════════════════════════════════════════
# RuleParser Tests
# ═══════════════════════════════════════════════════════════════════════════════

Describe 'RuleParser - ConvertTo-ConditionObject' {

    It 'Should parse a valid Equals condition' {
        $raw = @{ property = 'AccountEnabled'; operator = 'Equals'; value = $true }
        $cond = ConvertTo-ConditionObject -RawCondition $raw -RuleName 'TestRule'

        $cond.Property | Should -Be 'AccountEnabled'
        $cond.Operator | Should -Be 'Equals'
        $cond.Value    | Should -Be $true
    }

    It 'Should default operator to Equals when omitted' {
        $raw  = @{ property = 'DisplayName'; value = 'Test' }
        $cond = ConvertTo-ConditionObject -RawCondition $raw -RuleName 'TestRule'

        $cond.Operator | Should -Be 'Equals'
    }

    It 'Should allow null value for Exists operator' {
        $raw  = @{ property = 'Notes'; operator = 'Exists' }
        $cond = ConvertTo-ConditionObject -RawCondition $raw -RuleName 'TestRule'

        $cond.Operator | Should -Be 'Exists'
        $cond.Value    | Should -BeNullOrEmpty
    }

    It 'Should throw when property field is missing' {
        $raw = @{ operator = 'Equals'; value = 'x' }
        { ConvertTo-ConditionObject -RawCondition $raw -RuleName 'TestRule' } | Should -Throw
    }

    It 'Should throw for an unsupported operator' {
        $raw = @{ property = 'DisplayName'; operator = 'Between'; value = 'x' }
        { ConvertTo-ConditionObject -RawCondition $raw -RuleName 'TestRule' } | Should -Throw
    }

    It 'Should throw when Equals operator has no value' {
        $raw = @{ property = 'UserType'; operator = 'Equals' }
        { ConvertTo-ConditionObject -RawCondition $raw -RuleName 'TestRule' } | Should -Throw
    }

    It 'Should throw when GreaterThan operator has no value' {
        $raw = @{ property = 'MemberCount'; operator = 'GreaterThan' }
        { ConvertTo-ConditionObject -RawCondition $raw -RuleName 'TestRule' } | Should -Throw
    }

    It 'Should accept all valid operators without throwing' {
        $validOps = @('Equals','NotEquals','Contains','NotContains','Exists','NotExists','IsTrue','IsFalse','GreaterThan','LessThan')
        foreach ($op in $validOps) {
            $needsValue = $op -in @('Equals','NotEquals','Contains','NotContains','GreaterThan','LessThan')
            $raw = @{ property = 'Prop'; operator = $op }
            if ($needsValue) { $raw['value'] = 'x' }
            { ConvertTo-ConditionObject -RawCondition $raw -RuleName 'TestRule' } | Should -Not -Throw
        }
    }
}

Describe 'RuleParser - ConvertTo-RuleObject' {

    It 'Should parse a valid rule with all fields' {
        $raw = @{
            name        = 'My Rule'
            description = 'Desc'
            target      = 'Users'
            filter      = "UserType eq 'Guest'"
            conditions  = @(
                @{ property = 'AccountEnabled'; operator = 'IsTrue' }
            )
        }
        $rule = ConvertTo-RuleObject -RawRule $raw

        $rule.Name        | Should -Be 'My Rule'
        $rule.Description | Should -Be 'Desc'
        $rule.Target      | Should -Be 'Users'
        $rule.Filter      | Should -Be "UserType eq 'Guest'"
        $rule.Conditions.Count | Should -Be 1
    }

    It 'Should default description and filter to empty string when omitted' {
        $raw = @{
            name       = 'Simple Rule'
            target     = 'Groups'
            conditions = @(@{ property = 'Owners'; operator = 'Exists' })
        }
        $rule = ConvertTo-RuleObject -RawRule $raw

        $rule.Description | Should -Be ''
        $rule.Filter      | Should -Be ''
    }

    It 'Should throw when name is missing' {
        $raw = @{ target = 'Users'; conditions = @(@{ property = 'X'; operator = 'Exists' }) }
        { ConvertTo-RuleObject -RawRule $raw } | Should -Throw
    }

    It 'Should throw when target is missing' {
        $raw = @{ name = 'R'; conditions = @(@{ property = 'X'; operator = 'Exists' }) }
        { ConvertTo-RuleObject -RawRule $raw } | Should -Throw
    }

    It 'Should throw when conditions is missing' {
        $raw = @{ name = 'R'; target = 'Users' }
        { ConvertTo-RuleObject -RawRule $raw } | Should -Throw
    }

    It 'Should throw for an unsupported target' {
        $raw = @{
            name       = 'R'
            target     = 'Devices'
            conditions = @(@{ property = 'X'; operator = 'Exists' })
        }
        { ConvertTo-RuleObject -RawRule $raw } | Should -Throw
    }

    It 'Should accept all valid targets' {
        $validTargets = @('Users','Groups','EnterpriseApplications','AppRoleAssignments','DirectoryRoles')
        foreach ($t in $validTargets) {
            $raw = @{
                name       = "Rule-$t"
                target     = $t
                conditions = @(@{ property = 'X'; operator = 'Exists' })
            }
            { ConvertTo-RuleObject -RawRule $raw } | Should -Not -Throw
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# Condition Evaluator Tests
# ═══════════════════════════════════════════════════════════════════════════════

Describe 'Test-Condition - Exists / NotExists' {

    It 'Exists: returns true when property has a non-null, non-empty value' {
        $obj  = [PSCustomObject]@{ Notes = 'some notes' }
        $cond = [PSCustomObject]@{ Property = 'Notes'; Operator = 'Exists'; Value = $null }
        Test-Condition -Object $obj -Condition $cond | Should -BeTrue
    }

    It 'Exists: returns false when property is null' {
        $obj  = [PSCustomObject]@{ Notes = $null }
        $cond = [PSCustomObject]@{ Property = 'Notes'; Operator = 'Exists'; Value = $null }
        Test-Condition -Object $obj -Condition $cond | Should -BeFalse
    }

    It 'Exists: returns false when property is empty string' {
        $obj  = [PSCustomObject]@{ Notes = '' }
        $cond = [PSCustomObject]@{ Property = 'Notes'; Operator = 'Exists'; Value = $null }
        Test-Condition -Object $obj -Condition $cond | Should -BeFalse
    }

    It 'Exists: returns false when property is an empty array' {
        $obj  = [PSCustomObject]@{ Owners = @() }
        $cond = [PSCustomObject]@{ Property = 'Owners'; Operator = 'Exists'; Value = $null }
        Test-Condition -Object $obj -Condition $cond | Should -BeFalse
    }

    It 'Exists: returns true when property is a non-empty array' {
        $obj  = [PSCustomObject]@{ Owners = @('user1') }
        $cond = [PSCustomObject]@{ Property = 'Owners'; Operator = 'Exists'; Value = $null }
        Test-Condition -Object $obj -Condition $cond | Should -BeTrue
    }

    It 'Exists: returns false when property is missing from object' {
        $obj  = [PSCustomObject]@{ OtherProp = 'value' }
        $cond = [PSCustomObject]@{ Property = 'Notes'; Operator = 'Exists'; Value = $null }
        Test-Condition -Object $obj -Condition $cond | Should -BeFalse
    }

    It 'NotExists: returns true when property is null' {
        $obj  = [PSCustomObject]@{ Notes = $null }
        $cond = [PSCustomObject]@{ Property = 'Notes'; Operator = 'NotExists'; Value = $null }
        Test-Condition -Object $obj -Condition $cond | Should -BeTrue
    }

    It 'NotExists: returns false when property has value' {
        $obj  = [PSCustomObject]@{ Notes = 'something' }
        $cond = [PSCustomObject]@{ Property = 'Notes'; Operator = 'NotExists'; Value = $null }
        Test-Condition -Object $obj -Condition $cond | Should -BeFalse
    }
}

Describe 'Test-Condition - Equals / NotEquals' {

    It 'Equals: matches string value (case-insensitive via -eq)' {
        $obj  = [PSCustomObject]@{ UserType = 'Guest' }
        $cond = [PSCustomObject]@{ Property = 'UserType'; Operator = 'Equals'; Value = 'Guest' }
        Test-Condition -Object $obj -Condition $cond | Should -BeTrue
    }

    It 'Equals: fails when string value differs' {
        $obj  = [PSCustomObject]@{ UserType = 'Member' }
        $cond = [PSCustomObject]@{ Property = 'UserType'; Operator = 'Equals'; Value = 'Guest' }
        Test-Condition -Object $obj -Condition $cond | Should -BeFalse
    }

    It 'Equals: matches boolean value true' {
        $obj  = [PSCustomObject]@{ AccountEnabled = $true }
        $cond = [PSCustomObject]@{ Property = 'AccountEnabled'; Operator = 'Equals'; Value = $true }
        Test-Condition -Object $obj -Condition $cond | Should -BeTrue
    }

    It 'Equals: fails when boolean value differs' {
        $obj  = [PSCustomObject]@{ AccountEnabled = $false }
        $cond = [PSCustomObject]@{ Property = 'AccountEnabled'; Operator = 'Equals'; Value = $true }
        Test-Condition -Object $obj -Condition $cond | Should -BeFalse
    }

    It 'NotEquals: returns true when values differ' {
        $obj  = [PSCustomObject]@{ PrincipalType = 'User' }
        $cond = [PSCustomObject]@{ Property = 'PrincipalType'; Operator = 'NotEquals'; Value = 'Group' }
        Test-Condition -Object $obj -Condition $cond | Should -BeTrue
    }

    It 'NotEquals: returns false when values match' {
        $obj  = [PSCustomObject]@{ PrincipalType = 'Group' }
        $cond = [PSCustomObject]@{ Property = 'PrincipalType'; Operator = 'NotEquals'; Value = 'Group' }
        Test-Condition -Object $obj -Condition $cond | Should -BeFalse
    }
}

Describe 'Test-Condition - IsTrue / IsFalse' {

    It 'IsTrue: returns true when property is $true' {
        $obj  = [PSCustomObject]@{ IsVisibleInLaunchpad = $true }
        $cond = [PSCustomObject]@{ Property = 'IsVisibleInLaunchpad'; Operator = 'IsTrue'; Value = $null }
        Test-Condition -Object $obj -Condition $cond | Should -BeTrue
    }

    It 'IsTrue: returns false when property is $false' {
        $obj  = [PSCustomObject]@{ IsVisibleInLaunchpad = $false }
        $cond = [PSCustomObject]@{ Property = 'IsVisibleInLaunchpad'; Operator = 'IsTrue'; Value = $null }
        Test-Condition -Object $obj -Condition $cond | Should -BeFalse
    }

    It 'IsFalse: returns true when property is $false' {
        $obj  = [PSCustomObject]@{ AccountEnabled = $false }
        $cond = [PSCustomObject]@{ Property = 'AccountEnabled'; Operator = 'IsFalse'; Value = $null }
        Test-Condition -Object $obj -Condition $cond | Should -BeTrue
    }

    It 'IsFalse: returns false when property is $true' {
        $obj  = [PSCustomObject]@{ AccountEnabled = $true }
        $cond = [PSCustomObject]@{ Property = 'AccountEnabled'; Operator = 'IsFalse'; Value = $null }
        Test-Condition -Object $obj -Condition $cond | Should -BeFalse
    }
}

Describe 'Test-Condition - Contains / NotContains' {

    It 'Contains: returns true when string includes substring' {
        $obj  = [PSCustomObject]@{ DisplayName = 'Contoso Marketing App' }
        $cond = [PSCustomObject]@{ Property = 'DisplayName'; Operator = 'Contains'; Value = 'Marketing' }
        Test-Condition -Object $obj -Condition $cond | Should -BeTrue
    }

    It 'Contains: returns false when string does not include substring' {
        $obj  = [PSCustomObject]@{ DisplayName = 'Contoso HR App' }
        $cond = [PSCustomObject]@{ Property = 'DisplayName'; Operator = 'Contains'; Value = 'Marketing' }
        Test-Condition -Object $obj -Condition $cond | Should -BeFalse
    }

    It 'NotContains: returns true when string does not include substring' {
        $obj  = [PSCustomObject]@{ DisplayName = 'Contoso HR App' }
        $cond = [PSCustomObject]@{ Property = 'DisplayName'; Operator = 'NotContains'; Value = 'Marketing' }
        Test-Condition -Object $obj -Condition $cond | Should -BeTrue
    }

    It 'NotContains: returns false when string includes substring' {
        $obj  = [PSCustomObject]@{ DisplayName = 'Contoso Marketing App' }
        $cond = [PSCustomObject]@{ Property = 'DisplayName'; Operator = 'NotContains'; Value = 'Marketing' }
        Test-Condition -Object $obj -Condition $cond | Should -BeFalse
    }
}

Describe 'Test-Condition - GreaterThan / LessThan' {

    It 'GreaterThan: returns true when value is greater' {
        $obj  = [PSCustomObject]@{ MemberCount = 10 }
        $cond = [PSCustomObject]@{ Property = 'MemberCount'; Operator = 'GreaterThan'; Value = 5 }
        Test-Condition -Object $obj -Condition $cond | Should -BeTrue
    }

    It 'GreaterThan: returns false when value is equal' {
        $obj  = [PSCustomObject]@{ MemberCount = 5 }
        $cond = [PSCustomObject]@{ Property = 'MemberCount'; Operator = 'GreaterThan'; Value = 5 }
        Test-Condition -Object $obj -Condition $cond | Should -BeFalse
    }

    It 'GreaterThan: returns false when value is less' {
        $obj  = [PSCustomObject]@{ MemberCount = 3 }
        $cond = [PSCustomObject]@{ Property = 'MemberCount'; Operator = 'GreaterThan'; Value = 5 }
        Test-Condition -Object $obj -Condition $cond | Should -BeFalse
    }

    It 'LessThan: returns true when value is less' {
        $obj  = [PSCustomObject]@{ MemberCount = 3 }
        $cond = [PSCustomObject]@{ Property = 'MemberCount'; Operator = 'LessThan'; Value = 6 }
        Test-Condition -Object $obj -Condition $cond | Should -BeTrue
    }

    It 'LessThan: returns false when value is equal' {
        $obj  = [PSCustomObject]@{ MemberCount = 6 }
        $cond = [PSCustomObject]@{ Property = 'MemberCount'; Operator = 'LessThan'; Value = 6 }
        Test-Condition -Object $obj -Condition $cond | Should -BeFalse
    }

    It 'LessThan: returns false when value is greater' {
        $obj  = [PSCustomObject]@{ MemberCount = 10 }
        $cond = [PSCustomObject]@{ Property = 'MemberCount'; Operator = 'LessThan'; Value = 6 }
        Test-Condition -Object $obj -Condition $cond | Should -BeFalse
    }

    It 'GreaterThan: returns false for non-numeric property' {
        $obj  = [PSCustomObject]@{ MemberCount = 'not-a-number' }
        $cond = [PSCustomObject]@{ Property = 'MemberCount'; Operator = 'GreaterThan'; Value = 0 }
        Test-Condition -Object $obj -Condition $cond | Should -BeFalse
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# Test-ObjectAgainstRule Tests
# ═══════════════════════════════════════════════════════════════════════════════

Describe 'Test-ObjectAgainstRule' {

    It 'Returns IsCompliant=true when all conditions pass' {
        $obj  = [PSCustomObject]@{ AccountEnabled = $true; Notes = 'has notes' }
        $rule = [PSCustomObject]@{
            Name   = 'TestRule'
            Conditions = @(
                [PSCustomObject]@{ Property = 'AccountEnabled'; Operator = 'IsTrue';  Value = $null },
                [PSCustomObject]@{ Property = 'Notes';          Operator = 'Exists';  Value = $null }
            )
        }
        $result = Test-ObjectAgainstRule -Object $obj -Rule $rule
        $result.IsCompliant | Should -BeTrue
        $result.FailedConditions.Count | Should -Be 0
    }

    It 'Returns IsCompliant=false when one condition fails' {
        $obj  = [PSCustomObject]@{ AccountEnabled = $true; Notes = $null }
        $rule = [PSCustomObject]@{
            Name   = 'TestRule'
            Conditions = @(
                [PSCustomObject]@{ Property = 'AccountEnabled'; Operator = 'IsTrue'; Value = $null },
                [PSCustomObject]@{ Property = 'Notes';          Operator = 'Exists'; Value = $null }
            )
        }
        $result = Test-ObjectAgainstRule -Object $obj -Rule $rule
        $result.IsCompliant | Should -BeFalse
        $result.FailedConditions.Count | Should -Be 1
    }

    It 'Reports all failed conditions when multiple conditions fail' {
        $obj  = [PSCustomObject]@{ AccountEnabled = $false; Notes = '' }
        $rule = [PSCustomObject]@{
            Name   = 'TestRule'
            Conditions = @(
                [PSCustomObject]@{ Property = 'AccountEnabled'; Operator = 'IsTrue'; Value = $null },
                [PSCustomObject]@{ Property = 'Notes';          Operator = 'Exists'; Value = $null }
            )
        }
        $result = Test-ObjectAgainstRule -Object $obj -Rule $rule
        $result.IsCompliant | Should -BeFalse
        $result.FailedConditions.Count | Should -Be 2
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# ReportGenerator Tests
# ═══════════════════════════════════════════════════════════════════════════════

Describe 'ConvertTo-HtmlReport' {

    BeforeAll {
        Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

        $script:summary = [PSCustomObject]@{
            TotalRules       = 3
            TotalObjects     = 10
            ViolatingObjects = 2
            CompliantObjects = 8
            GeneratedAt      = (Get-Date).ToString('o')
        }
    }

    It 'Produces valid HTML with no violations' {
        $html = ConvertTo-HtmlReport -Violations @() -Summary $script:summary
        $html | Should -Match '<!DOCTYPE html>'
        $html | Should -Match 'No violations detected'
        $html | Should -Match 'Rules Evaluated'
    }

    It 'Includes violation rows in HTML when violations exist' {
        $violations = @(
            [PSCustomObject]@{
                RuleName        = 'Test Rule'
                ObjectType      = 'Users'
                ObjectId        = 'abc-123'
                DisplayName     = 'John Doe'
                ViolationReason = "Property 'Notes' failed operator 'Exists'"
            }
        )
        $html = ConvertTo-HtmlReport -Violations $violations -Summary $script:summary
        $html | Should -Match 'Test Rule'
        $html | Should -Match 'John Doe'
        $html | Should -Match 'abc-123'
        $html | Should -Not -Match 'No violations detected'
    }

    It 'HTML-encodes potentially dangerous characters in violation data' {
        $violations = @(
            [PSCustomObject]@{
                RuleName        = '<script>alert(1)</script>'
                ObjectType      = 'Users'
                ObjectId        = 'id-1'
                DisplayName     = 'Test & User'
                ViolationReason = 'Some reason'
            }
        )
        $html = ConvertTo-HtmlReport -Violations $violations -Summary $script:summary
        # Should NOT contain raw unescaped script tag
        $html | Should -Not -Match '<script>alert'
        # Should contain HTML-encoded version
        $html | Should -Match '&lt;script&gt;'
    }

    It 'Includes summary card values in HTML' {
        $html = ConvertTo-HtmlReport -Violations @() -Summary $script:summary
        $html | Should -Match '10'   # TotalObjects
        $html | Should -Match '3'    # TotalRules
        $html | Should -Match '8'    # CompliantObjects
        $html | Should -Match '2'    # ViolatingObjects
    }

    It 'Accepts a custom title' {
        $html = ConvertTo-HtmlReport -Violations @() -Summary $script:summary -Title 'My Custom Report'
        $html | Should -Match 'My Custom Report'
    }
}

Describe 'Export-ComplianceReport' {

    BeforeAll {
        $script:summary = [PSCustomObject]@{
            TotalRules       = 1
            TotalObjects     = 5
            ViolatingObjects = 1
            CompliantObjects = 4
            GeneratedAt      = (Get-Date).ToString('o')
        }
        $script:violations = @(
            [PSCustomObject]@{
                RuleName        = 'Rule A'
                ObjectType      = 'Groups'
                ObjectId        = 'grp-001'
                DisplayName     = 'Test Group'
                ViolationReason = 'No owners'
            }
        )
    }

    It 'Returns HTML content as a string' {
        $result = Export-ComplianceReport -Violations $script:violations -Summary $script:summary -ShowSummary $false
        $result | Should -BeOfType [string]
        $result | Should -Match '<!DOCTYPE html>'
    }

    It 'Writes HTML to file when OutputPath is specified' {
        $tmpFile = [System.IO.Path]::GetTempFileName() + '.html'
        try {
            Export-ComplianceReport -Violations $script:violations -Summary $script:summary `
                -OutputPath $tmpFile -ShowSummary $false
            Test-Path -Path $tmpFile | Should -BeTrue
            $content = Get-Content -Path $tmpFile -Raw
            $content | Should -Match '<!DOCTYPE html>'
        }
        finally {
            if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force }
        }
    }

    It 'Does not throw when OutputPath is empty' {
        { Export-ComplianceReport -Violations @() -Summary $script:summary -OutputPath '' -ShowSummary $false } |
            Should -Not -Throw
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# Integration-style Tests (mocked Graph)
# ═══════════════════════════════════════════════════════════════════════════════

Describe 'Invoke-EntraComplianceCheck - Integration (Mocked Graph)' {

    BeforeAll {
        $script:repoRoot = Split-Path -Parent $PSScriptRoot
        $script:rulesFile = Join-Path $script:repoRoot 'compliance_rules.yaml'
    }

    It 'Throws when rules file does not exist' {
        { Invoke-EntraComplianceCheck -RulesPath '/nonexistent/path/rules.yaml' } |
            Should -Throw
    }

    It 'Runs without error when mocking Graph calls and returns violations array with PassThru' {
        # Create a minimal temporary rules file
        $tmpRules = [System.IO.Path]::GetTempFileName() + '.yaml'
        try {
            @'
rules:
  - name: "Test Rule"
    target: "Users"
    conditions:
      - property: "AccountEnabled"
        operator: "IsTrue"
'@ | Set-Content -Path $tmpRules -Encoding UTF8

            # Mock ConvertFrom-Yaml to return a predictable structure
            Mock -CommandName ConvertFrom-Yaml -MockWith {
                @{
                    rules = @(
                        @{
                            name       = 'Test Rule'
                            target     = 'Users'
                            conditions = @(@{ property = 'AccountEnabled'; operator = 'IsTrue' })
                        }
                    )
                }
            }

            # Mock Graph connection checks
            Mock -CommandName Get-MgContext -MockWith { [PSCustomObject]@{ ClientId = 'mock' } }
            Mock -CommandName Get-Module    -MockWith { $true }

            # Mock the data collector to return test objects
            Mock -CommandName Get-EntraObjects -MockWith {
                @(
                    [PSCustomObject]@{ ObjectId = 'usr-1'; DisplayName = 'Active User';   AccountEnabled = $true  },
                    [PSCustomObject]@{ ObjectId = 'usr-2'; DisplayName = 'Disabled User'; AccountEnabled = $false }
                )
            }

            $violations = Invoke-EntraComplianceCheck -RulesPath $tmpRules -PassThru

            $violations | Should -Not -BeNullOrEmpty
            $violations.Count | Should -Be 1
            $violations[0].ObjectId    | Should -Be 'usr-2'
            $violations[0].DisplayName | Should -Be 'Disabled User'
            $violations[0].RuleName    | Should -Be 'Test Rule'
        }
        finally {
            if (Test-Path $tmpRules) { Remove-Item $tmpRules -Force }
        }
    }

    It 'Returns empty violations array when all objects are compliant' {
        $tmpRules = [System.IO.Path]::GetTempFileName() + '.yaml'
        try {
            @'
rules:
  - name: "All Pass Rule"
    target: "Groups"
    conditions:
      - property: "SecurityEnabled"
        operator: "IsTrue"
'@ | Set-Content -Path $tmpRules -Encoding UTF8

            Mock -CommandName ConvertFrom-Yaml -MockWith {
                @{
                    rules = @(
                        @{
                            name       = 'All Pass Rule'
                            target     = 'Groups'
                            conditions = @(@{ property = 'SecurityEnabled'; operator = 'IsTrue' })
                        }
                    )
                }
            }

            Mock -CommandName Get-MgContext    -MockWith { [PSCustomObject]@{ ClientId = 'mock' } }
            Mock -CommandName Get-Module       -MockWith { $true }
            Mock -CommandName Get-EntraObjects -MockWith {
                @(
                    [PSCustomObject]@{ ObjectId = 'grp-1'; DisplayName = 'Group A'; SecurityEnabled = $true },
                    [PSCustomObject]@{ ObjectId = 'grp-2'; DisplayName = 'Group B'; SecurityEnabled = $true }
                )
            }

            $violations = Invoke-EntraComplianceCheck -RulesPath $tmpRules -PassThru
            @($violations).Count | Should -Be 0
        }
        finally {
            if (Test-Path $tmpRules) { Remove-Item $tmpRules -Force }
        }
    }
}
