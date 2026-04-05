#Requires -Version 5.1
<#
.SYNOPSIS
    Rule Parser - Reads and validates the compliance_rules.yaml configuration file.

.DESCRIPTION
    This module is responsible for:
      - Loading the powershell-yaml module (or falling back to a bundled minimal parser).
      - Reading and deserialising a YAML rules file.
      - Validating the structure of each rule (required fields, supported operators, etc.).
      - Returning a typed collection of rule objects consumed by the main auditor.

.NOTES
    Part of the Entra ID Compliance Auditor toolkit.
    Supported operators: Equals, NotEquals, Contains, NotContains, Exists, NotExists,
                         IsTrue, IsFalse, GreaterThan, LessThan.
#>

Set-StrictMode -Version Latest

#region ── Constants ──────────────────────────────────────────────────────────

$script:ValidOperators = @(
    'Equals', 'NotEquals', 'Contains', 'NotContains',
    'Exists', 'NotExists', 'IsTrue', 'IsFalse',
    'GreaterThan', 'LessThan'
)

$script:ValidTargets = @(
    'Users', 'Groups', 'EnterpriseApplications',
    'AppRoleAssignments', 'DirectoryRoles'
)

#endregion

#region ── YAML Loading ───────────────────────────────────────────────────────

function Import-YamlModule {
    <#
    .SYNOPSIS
        Ensures the powershell-yaml module is available; imports it if found.
    .OUTPUTS
        [bool] $true if the module is available, $false otherwise.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (Get-Command -Name 'ConvertFrom-Yaml' -ErrorAction SilentlyContinue) {
        return $true
    }

    if (Get-Module -ListAvailable -Name 'powershell-yaml' -ErrorAction SilentlyContinue) {
        try {
            Import-Module -Name 'powershell-yaml' -ErrorAction Stop
            return $true
        }
        catch {
            Write-Warning "Failed to import 'powershell-yaml': $_"
        }
    }

    Write-Error ("The 'powershell-yaml' module is required but was not found. " +
        "Install it with: Install-Module -Name powershell-yaml -Scope CurrentUser")
    return $false
}

#endregion

#region ── Rule Parsing ───────────────────────────────────────────────────────

function ConvertTo-RuleObject {
    <#
    .SYNOPSIS
        Converts a raw hashtable (deserialised from YAML) into a validated rule PSCustomObject.
    .PARAMETER RawRule
        Hashtable representing a single rule entry from the YAML file.
    .OUTPUTS
        [PSCustomObject] A typed, validated rule object.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$RawRule
    )

    # Required fields
    foreach ($field in @('name', 'target', 'conditions')) {
        if (-not $RawRule.ContainsKey($field) -or $null -eq $RawRule[$field]) {
            throw "Rule is missing required field '$field'. Rule: $($RawRule | ConvertTo-Json -Compress -Depth 3)"
        }
    }

    $ruleName   = [string]$RawRule['name']
    $target     = [string]$RawRule['target']
    $description = if ($RawRule.ContainsKey('description')) { [string]$RawRule['description'] } else { '' }
    $filter      = if ($RawRule.ContainsKey('filter'))      { [string]$RawRule['filter'] }      else { '' }

    # Validate target
    if ($target -notin $script:ValidTargets) {
        throw "Rule '$ruleName' has an unsupported target '$target'. Valid targets: $($script:ValidTargets -join ', ')"
    }

    # Parse conditions
    $conditions = @()
    foreach ($rawCond in $RawRule['conditions']) {
        $conditions += ConvertTo-ConditionObject -RawCondition $rawCond -RuleName $ruleName
    }

    if ($conditions.Count -eq 0) {
        throw "Rule '$ruleName' has no valid conditions."
    }

    [PSCustomObject]@{
        Name        = $ruleName
        Description = $description
        Target      = $target
        Filter      = $filter
        Conditions  = $conditions
    }
}

function ConvertTo-ConditionObject {
    <#
    .SYNOPSIS
        Converts a raw condition hashtable into a validated condition PSCustomObject.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        $RawCondition,

        [Parameter(Mandatory)]
        [string]$RuleName
    )

    if (-not ($RawCondition -is [hashtable])) {
        throw "Condition in rule '$RuleName' is not a valid mapping."
    }

    if (-not $RawCondition.ContainsKey('property')) {
        throw "A condition in rule '$RuleName' is missing the required 'property' field."
    }

    $property = [string]$RawCondition['property']
    $operator = if ($RawCondition.ContainsKey('operator')) { [string]$RawCondition['operator'] } else { 'Equals' }
    $value    = if ($RawCondition.ContainsKey('value'))    { $RawCondition['value'] }             else { $null }

    # Validate operator
    if ($operator -notin $script:ValidOperators) {
        throw ("Condition in rule '$RuleName' has unsupported operator '$operator'. " +
            "Valid operators: $($script:ValidOperators -join ', ')")
    }

    # Operators that require a value
    $valueRequiredOperators = @('Equals', 'NotEquals', 'Contains', 'NotContains', 'GreaterThan', 'LessThan')
    if ($operator -in $valueRequiredOperators -and $null -eq $value) {
        throw "Condition in rule '$RuleName' uses operator '$operator' but is missing a 'value'."
    }

    [PSCustomObject]@{
        Property = $property
        Operator = $operator
        Value    = $value
    }
}

#endregion

#region ── Public API ─────────────────────────────────────────────────────────

function Import-ComplianceRules {
    <#
    .SYNOPSIS
        Loads and parses a YAML compliance rules file.
    .PARAMETER Path
        Path to the YAML file containing compliance rules.
    .OUTPUTS
        [PSCustomObject[]] An array of rule objects ready for evaluation.
    .EXAMPLE
        $rules = Import-ComplianceRules -Path './compliance_rules.yaml'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    # Resolve path
    if (-not (Test-Path -Path $Path -PathType Leaf)) {
        throw "Compliance rules file not found: '$Path'"
    }
    $resolvedPath = (Resolve-Path -Path $Path).Path

    # Ensure YAML module is available
    if (-not (Import-YamlModule)) {
        throw "Cannot load compliance rules: 'powershell-yaml' module is unavailable."
    }

    # Read file
    Write-Verbose "Loading compliance rules from: $resolvedPath"
    try {
        $rawYaml = Get-Content -Path $resolvedPath -Raw -ErrorAction Stop
    }
    catch {
        throw "Failed to read rules file '$resolvedPath': $_"
    }

    # Deserialise
    try {
        $parsed = ConvertFrom-Yaml -Yaml $rawYaml -ErrorAction Stop
    }
    catch {
        throw "Failed to parse YAML in '$resolvedPath': $_"
    }

    if ($null -eq $parsed -or -not $parsed.ContainsKey('rules')) {
        throw "The YAML file '$resolvedPath' must contain a top-level 'rules' key."
    }

    $rawRules = $parsed['rules']
    if ($null -eq $rawRules -or $rawRules.Count -eq 0) {
        Write-Warning "No rules found in '$resolvedPath'."
        return @()
    }

    # Convert and validate each rule
    $rules = @()
    foreach ($rawRule in $rawRules) {
        try {
            $rules += ConvertTo-RuleObject -RawRule $rawRule
        }
        catch {
            Write-Warning "Skipping invalid rule: $_"
        }
    }

    Write-Verbose "Loaded $($rules.Count) rule(s) from '$resolvedPath'."
    return $rules
}

#endregion
