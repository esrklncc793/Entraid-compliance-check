#Requires -Version 5.1
<#
.SYNOPSIS
    Entra ID Compliance Auditor - Main Script

.DESCRIPTION
    This script orchestrates the end-to-end compliance check against Entra ID objects.

    It:
      1. Loads compliance rules from a YAML configuration file (via RuleParser.ps1).
      2. Fetches Entra ID objects for each rule's target type (via EntraDataCollector.ps1).
      3. Evaluates each object against the rule's conditions.
      4. Collects violations into a structured result set.
      5. Generates a console summary and optionally an HTML report (via ReportGenerator.ps1).

.PARAMETER RulesPath
    Path to the YAML compliance rules file. Defaults to 'compliance_rules.yaml' in the
    same directory as this script.

.PARAMETER OutputHtmlPath
    Optional. If specified, an HTML report is written to this path.

.PARAMETER PassThru
    If specified, the function returns the violations array to the pipeline.

.EXAMPLE
    # Basic run using the default rules file
    .\EntraComplianceAuditor.ps1

.EXAMPLE
    # Specify a custom rules file and output an HTML report
    .\EntraComplianceAuditor.ps1 -RulesPath 'C:\rules\my_rules.yaml' -OutputHtmlPath 'C:\reports\compliance.html'

.EXAMPLE
    # Import and call the function directly
    . .\EntraComplianceAuditor.ps1
    $violations = Invoke-EntraComplianceCheck -RulesPath './compliance_rules.yaml' -PassThru

.NOTES
    Prerequisites:
      - PowerShell 5.1 or later (PowerShell 7+ recommended)
      - powershell-yaml module:   Install-Module -Name powershell-yaml -Scope CurrentUser
      - Microsoft.Graph modules:  Install-Module -Name Microsoft.Graph -Scope CurrentUser
      - Active Graph session:     Connect-MgGraph -Scopes 'User.Read.All','Group.Read.All',
                                      'Application.Read.All','Directory.Read.All'
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$RulesPath      = '',
    [string]$OutputHtmlPath = '',
    [switch]$PassThru
)

Set-StrictMode -Version Latest

#region ── Module Dot-Sourcing ────────────────────────────────────────────────

$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# Allow running from the repository root or from within ./src
$srcRoot = if (Test-Path -Path (Join-Path $scriptRoot 'RuleParser.ps1')) {
    $scriptRoot
}
elseif (Test-Path -Path (Join-Path $scriptRoot 'src' 'RuleParser.ps1')) {
    Join-Path $scriptRoot 'src'
}
else {
    throw "Cannot locate supporting modules (RuleParser.ps1, EntraDataCollector.ps1, ReportGenerator.ps1)."
}

. (Join-Path $srcRoot 'RuleParser.ps1')
. (Join-Path $srcRoot 'EntraDataCollector.ps1')
. (Join-Path $srcRoot 'ReportGenerator.ps1')

#endregion

#region ── Condition Evaluator ────────────────────────────────────────────────

function Test-Condition {
    <#
    .SYNOPSIS
        Evaluates a single condition against a property value extracted from an Entra object.
    .PARAMETER Object
        The Entra object (PSCustomObject) to evaluate.
    .PARAMETER Condition
        A condition PSCustomObject with Property, Operator, and Value fields.
    .OUTPUTS
        [bool] $true if the condition is satisfied; $false otherwise.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Object,

        [Parameter(Mandatory)]
        [PSCustomObject]$Condition
    )

    # Retrieve the property value from the object
    $propValue = $null
    if ($Object.PSObject.Properties.Name -contains $Condition.Property) {
        $propValue = $Object.($Condition.Property)
    }

    switch ($Condition.Operator) {

        'Exists' {
            if ($null -eq $propValue)   { return $false }
            if ($propValue -is [string] -and [string]::IsNullOrWhiteSpace($propValue)) { return $false }
            if ($propValue -is [System.Collections.IEnumerable] -and
                -not ($propValue -is [string])) {
                $count = 0
                foreach ($_ in $propValue) { $count++ }
                return $count -gt 0
            }
            return $true
        }

        'NotExists' {
            if ($null -eq $propValue)   { return $true }
            if ($propValue -is [string] -and [string]::IsNullOrWhiteSpace($propValue)) { return $true }
            if ($propValue -is [System.Collections.IEnumerable] -and
                -not ($propValue -is [string])) {
                $count = 0
                foreach ($_ in $propValue) { $count++ }
                return $count -eq 0
            }
            return $false
        }

        'IsTrue'  { return ($propValue -eq $true) }
        'IsFalse' { return ($propValue -eq $false) }

        'Equals' {
            if ($null -eq $propValue)         { return ($null -eq $Condition.Value) }
            if ($propValue -is [bool])         { return ($propValue -eq [System.Convert]::ToBoolean($Condition.Value)) }
            if ($propValue -is [int] -or $propValue -is [long] -or $propValue -is [double]) {
                return ($propValue -eq $Condition.Value)
            }
            return ([string]$propValue -eq [string]$Condition.Value)
        }

        'NotEquals' {
            if ($null -eq $propValue)         { return ($null -ne $Condition.Value) }
            if ($propValue -is [bool])         { return ($propValue -ne [System.Convert]::ToBoolean($Condition.Value)) }
            if ($propValue -is [int] -or $propValue -is [long] -or $propValue -is [double]) {
                return ($propValue -ne $Condition.Value)
            }
            return ([string]$propValue -ne [string]$Condition.Value)
        }

        'Contains' {
            return ([string]$propValue -like "*$($Condition.Value)*")
        }

        'NotContains' {
            return ([string]$propValue -notlike "*$($Condition.Value)*")
        }

        'GreaterThan' {
            try { return ([double]$propValue -gt [double]$Condition.Value) }
            catch {
                Write-Verbose ("GreaterThan comparison failed for property '$($Condition.Property)': " +
                    "value '$propValue' is not numeric. Treating condition as not satisfied.")
                return $false
            }
        }

        'LessThan' {
            try { return ([double]$propValue -lt [double]$Condition.Value) }
            catch {
                Write-Verbose ("LessThan comparison failed for property '$($Condition.Property)': " +
                    "value '$propValue' is not numeric. Treating condition as not satisfied.")
                return $false
            }
        }

        default {
            Write-Warning "Unknown operator '$($Condition.Operator)' - condition treated as not satisfied."
            return $false
        }
    }
}

function Test-ObjectAgainstRule {
    <#
    .SYNOPSIS
        Evaluates all conditions in a rule against a single Entra object.
    .PARAMETER Object
        The Entra object to test.
    .PARAMETER Rule
        The rule containing one or more conditions (all conditions are AND-ed).
    .OUTPUTS
        [PSCustomObject] with IsCompliant ($bool) and FailedConditions (array of condition strings).
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Object,

        [Parameter(Mandatory)]
        [PSCustomObject]$Rule
    )

    $failedConditions = @()

    foreach ($condition in $Rule.Conditions) {
        $passed = Test-Condition -Object $Object -Condition $condition
        if (-not $passed) {
            $detail = "Property '$($condition.Property)' failed operator '$($condition.Operator)'"
            if ($null -ne $condition.Value) { $detail += " (expected value: '$($condition.Value)')" }
            $failedConditions += $detail
        }
    }

    [PSCustomObject]@{
        IsCompliant       = ($failedConditions.Count -eq 0)
        FailedConditions  = $failedConditions
    }
}

#endregion

#region ── Main Function ──────────────────────────────────────────────────────

function Invoke-EntraComplianceCheck {
    <#
    .SYNOPSIS
        Runs the Entra ID compliance check against all rules defined in the YAML file.
    .DESCRIPTION
        For each rule in the YAML file:
          1. Fetches Entra ID objects for the rule's target type.
          2. Evaluates every object against all conditions in the rule.
          3. Collects violations.
        Finally, generates a summary and (optionally) an HTML report.
    .PARAMETER RulesPath
        Path to the compliance_rules.yaml file.
    .PARAMETER OutputHtmlPath
        If specified, writes an HTML compliance report to this path.
    .PARAMETER PassThru
        If specified, returns the violations array to the pipeline.
    .OUTPUTS
        If PassThru is set: [PSCustomObject[]] array of violations.
        Otherwise: nothing returned to pipeline (summary written to host).
    .EXAMPLE
        Invoke-EntraComplianceCheck -RulesPath './compliance_rules.yaml' -OutputHtmlPath './report.html'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RulesPath,

        [string]$OutputHtmlPath = '',

        [switch]$PassThru
    )

    Write-Verbose "=== Entra ID Compliance Check Starting ==="

    # ── Step 1: Load rules ────────────────────────────────────────────────────
    Write-Verbose "Loading rules from: $RulesPath"
    $rules = Import-ComplianceRules -Path $RulesPath

    if (-not $rules -or $rules.Count -eq 0) {
        Write-Warning "No rules to evaluate. Exiting."
        return
    }

    Write-Verbose "Loaded $($rules.Count) rule(s)."

    # ── Step 2: Evaluate rules ────────────────────────────────────────────────
    $allViolations  = @()
    $totalObjects   = 0
    $violatingIds   = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($rule in $rules) {
        Write-Verbose "Processing rule: '$($rule.Name)' (target: $($rule.Target))"

        # Fetch objects for this target
        try {
            $objects = Get-EntraObjects -Target $rule.Target -Filter $rule.Filter
        }
        catch {
            Write-Warning "Could not fetch objects for rule '$($rule.Name)': $_"
            continue
        }

        if ($null -eq $objects -or @($objects).Count -eq 0) {
            Write-Verbose "No objects returned for rule '$($rule.Name)'."
            continue
        }

        $totalObjects += @($objects).Count

        # Evaluate each object
        foreach ($obj in $objects) {
            $result = Test-ObjectAgainstRule -Object $obj -Rule $rule

            if (-not $result.IsCompliant) {
                $violationReason = $result.FailedConditions -join '; '
                $objId = if ($obj.PSObject.Properties.Name -contains 'ObjectId') { $obj.ObjectId } else { 'N/A' }
                $displayName = if ($obj.PSObject.Properties.Name -contains 'DisplayName') { $obj.DisplayName } else { 'N/A' }

                $allViolations += [PSCustomObject]@{
                    RuleName        = $rule.Name
                    ObjectType      = $rule.Target
                    ObjectId        = $objId
                    DisplayName     = $displayName
                    ViolationReason = $violationReason
                }

                [void]$violatingIds.Add("$($rule.Target):$objId")
            }
        }
    }

    # ── Step 3: Build summary ─────────────────────────────────────────────────
    $summary = [PSCustomObject]@{
        TotalRules        = $rules.Count
        TotalObjects      = $totalObjects
        ViolatingObjects  = $violatingIds.Count
        CompliantObjects  = $totalObjects - $violatingIds.Count
        GeneratedAt       = (Get-Date).ToString('o')
    }

    # ── Step 4: Output ────────────────────────────────────────────────────────
    $null = Export-ComplianceReport `
        -Violations $allViolations `
        -Summary    $summary `
        -OutputPath $OutputHtmlPath `
        -ShowSummary $true

    Write-Verbose "=== Entra ID Compliance Check Complete ==="

    if ($PassThru) {
        return $allViolations
    }
}

#endregion

#region ── Script Entry Point ─────────────────────────────────────────────────
# When the script is run directly (not dot-sourced), execute the check automatically.
if ($MyInvocation.InvocationName -ne '.') {
    # Resolve default rules path if not provided
    if ([string]::IsNullOrWhiteSpace($RulesPath)) {
        $defaultRulesPath = Join-Path $scriptRoot '..' 'compliance_rules.yaml'
        if (-not (Test-Path -Path $defaultRulesPath)) {
            $defaultRulesPath = Join-Path $scriptRoot 'compliance_rules.yaml'
        }
        $RulesPath = $defaultRulesPath
    }

    $invokeParams = @{
        RulesPath = $RulesPath
    }
    if ($OutputHtmlPath) { $invokeParams['OutputHtmlPath'] = $OutputHtmlPath }
    if ($PassThru)       { $invokeParams['PassThru']       = $true }

    Invoke-EntraComplianceCheck @invokeParams
}
#endregion
