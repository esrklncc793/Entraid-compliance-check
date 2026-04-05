# Entra ID Compliance Auditor

A **PowerShell-based compliance auditing tool** for Microsoft Entra ID (formerly Azure Active Directory).  
It reads a declarative YAML configuration file and validates Entra ID objects — Users, Groups, Enterprise Applications, App Role Assignments, and Directory Roles — against defined standards using the Microsoft Graph PowerShell SDK.

---

## Features

- 📋 **Declarative YAML rules** — Define compliance rules without writing custom code
- 🔍 **Flexible condition engine** — 10 operators: `Equals`, `NotEquals`, `Contains`, `NotContains`, `Exists`, `NotExists`, `IsTrue`, `IsFalse`, `GreaterThan`, `LessThan`
- 🏷️ **Multiple target types** — Users, Groups, Enterprise Applications, App Role Assignments, Directory Roles
- 📊 **HTML reports** — Self-contained, styled HTML report with summary cards and violation table
- 🖥️ **Console output** — Formatted summary table written to the terminal
- 🔁 **Throttle-safe** — Automatic exponential back-off retry on Graph API HTTP 429 responses
- 🧪 **Pester tests** — Full test suite covering the rule parser, evaluator, and report generator
- 🧩 **Modular design** — Clear separation between the Rule Parser, Data Collector, Evaluator, and Report Generator

---

## Prerequisites

| Requirement | Command |
|---|---|
| PowerShell 5.1+ (7.x recommended) | — |
| `powershell-yaml` module | `Install-Module -Name powershell-yaml -Scope CurrentUser` |
| Microsoft Graph PS modules | `Install-Module -Name Microsoft.Graph -Scope CurrentUser` |
| Active Graph session | `Connect-MgGraph -Scopes 'User.Read.All','Group.Read.All','Application.Read.All','Directory.Read.All'` |

---

## Repository Structure

```
Entraid-compliance-check/
├── compliance_rules.yaml          # Sample compliance rules configuration
├── src/
│   ├── EntraComplianceAuditor.ps1 # Main script / entry point
│   ├── RuleParser.ps1             # YAML rule loader & validator
│   ├── EntraDataCollector.ps1     # Microsoft Graph data fetcher
│   └── ReportGenerator.ps1       # HTML & console report generator
└── tests/
    └── EntraComplianceAuditor.Tests.ps1  # Pester 5.x test suite
```

---

## Quick Start

```powershell
# 1. Authenticate with Microsoft Graph
Connect-MgGraph -Scopes 'User.Read.All','Group.Read.All','Application.Read.All','Directory.Read.All'

# 2. Run the compliance check (console output only)
.\src\EntraComplianceAuditor.ps1

# 3. Run with a custom rules file and generate an HTML report
.\src\EntraComplianceAuditor.ps1 -RulesPath '.\compliance_rules.yaml' -OutputHtmlPath '.\report.html'

# 4. Dot-source and call the function directly, capturing violations
. .\src\EntraComplianceAuditor.ps1
$violations = Invoke-EntraComplianceCheck -RulesPath '.\compliance_rules.yaml' -PassThru
$violations | Format-Table -AutoSize
```

---

## YAML Rules File Format

```yaml
rules:
  - name: "Enterprise App Visibility Check"
    description: "Visible apps must declare required permissions."  # optional
    target: "EnterpriseApplications"
    filter: ""                                                       # optional OData filter
    conditions:
      - property: "IsVisibleInLaunchpad"
        operator: "IsTrue"
      - property: "RequiredResourceAccess"
        operator: "Exists"

  - name: "Groups Must Have Owners"
    target: "Groups"
    conditions:
      - property: "Owners"
        operator: "Exists"
```

### Supported Targets

| Target | Graph Objects Fetched |
|---|---|
| `Users` | Entra ID user accounts |
| `Groups` | Security & M365 groups |
| `EnterpriseApplications` | Service principals |
| `AppRoleAssignments` | App role assignments across all service principals |
| `DirectoryRoles` | Activated directory roles with member counts |

### Supported Operators

| Operator | Description |
|---|---|
| `Equals` | Property equals value |
| `NotEquals` | Property does not equal value |
| `Contains` | String property contains substring |
| `NotContains` | String property does not contain substring |
| `Exists` | Property is not null / not empty |
| `NotExists` | Property is null or empty |
| `IsTrue` | Boolean property is `$true` |
| `IsFalse` | Boolean property is `$false` |
| `GreaterThan` | Numeric property is greater than value |
| `LessThan` | Numeric property is less than value |

---

## Running Tests

```powershell
# Install Pester 5.x if not already installed
Install-Module -Name Pester -MinimumVersion 5.0 -Scope CurrentUser -Force

# Run the test suite
Invoke-Pester -Path './tests/EntraComplianceAuditor.Tests.ps1' -Output Detailed
```

The tests run **without a live Graph connection** by mocking all Mg* commands.

---

## Output

### Console Summary

```
═══════════════════════════════════════════════════════════════
  Entra ID Compliance Check — Summary
═══════════════════════════════════════════════════════════════
  Rules Evaluated   : 12
  Objects Checked   : 150
  Compliant Objects : 142
  Violations Found  : 8
═══════════════════════════════════════════════════════════════

RuleName                          ObjectType  ObjectId  DisplayName       ViolationReason
--------                          ----------  --------  -----------       ---------------
Groups Must Have Owners           Groups      grp-001   Marketing Team    Property 'Owners' failed operator 'Exists'
Enterprise App Visibility Check   EA          sp-002    Contoso Portal    Property 'RequiredResourceAccess' failed operator 'Exists'
```

### HTML Report

The HTML report is a self-contained file with:
- Summary cards (rules evaluated, objects checked, compliant, violations)
- Styled violations table with rule name badges
- No external dependencies (pure inline CSS)

---

## Architecture

```
EntraComplianceAuditor.ps1
         │
         ├─► RuleParser.ps1
         │      Import-ComplianceRules()
         │      ConvertTo-RuleObject()
         │      ConvertTo-ConditionObject()
         │
         ├─► EntraDataCollector.ps1
         │      Get-EntraObjects()
         │      Get-EntraUsers / Get-EntraGroups / ...
         │      Invoke-GraphWithRetry()
         │
         ├─► [Condition Evaluator - inline in main script]
         │      Test-Condition()
         │      Test-ObjectAgainstRule()
         │
         └─► ReportGenerator.ps1
                Export-ComplianceReport()
                ConvertTo-HtmlReport()
                Write-ComplianceSummary()
```

---

## License

MIT