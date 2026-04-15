# EntraComplianceAuditor

A PowerShell module for auditing Microsoft Entra ID (Azure AD) tenant settings against configurable compliance rules.

## Features

- **Security Defaults** – detects whether Security Defaults are enabled.
- **Conditional Access** – checks for policies that block legacy authentication and require MFA for admins (and optionally all users).
- **MFA Policy** – inspects the Authentication Methods policy migration state.
- **Password Policy** – validates the organisation's password validity period.
- Structured, machine-readable output (`PSCustomObject` with `Status`, `Severity`, `Recommendation`, etc.).
- Optional JSON / CSV file export.
- Compliance rules are configurable via a YAML file.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| PowerShell 5.1 or later (7.x recommended) | |
| [Microsoft.Graph](https://learn.microsoft.com/en-us/powershell/microsoftgraph/) module | `Install-Module Microsoft.Graph -Scope CurrentUser` |
| Entra ID permissions | `Policy.Read.All`, `Directory.Read.All`, `UserAuthenticationMethod.Read.All` |

---

## Installation

Clone this repository and import the module directly:

```powershell
git clone https://github.com/esrklncc793/Entraid-compliance-check.git
Import-Module ./Entraid-compliance-check/EntraComplianceAuditor/EntraComplianceAuditor.psd1
```

---

## Quick Start

```powershell
# Connect to Microsoft Graph and run all checks
$report = Invoke-EntraComplianceCheck -Connect

# View the compliance score and summary
$report.ComplianceScore
$report.Summary

# See individual check results
$report.Results | Format-Table CheckName, Status, Severity, Description -AutoSize

# Export to JSON
Invoke-EntraComplianceCheck -Connect -OutputPath ./report.json -OutputFormat JSON
```

---

## Functions

### `Invoke-EntraComplianceCheck`

Main entry point. Optionally connects to Graph, runs checks, and returns a report.

| Parameter | Type | Description |
|---|---|---|
| `-TenantId` | `string` | Tenant to connect to (used with `-Connect`). |
| `-RulesPath` | `string` | Path to a custom `compliance-rules.yaml`. |
| `-CheckNames` | `string[]` | Subset of checks to run. Default: `All`. |
| `-OutputPath` | `string` | File path for the saved report. |
| `-OutputFormat` | `string` | `JSON`, `CSV`, or `None` (default). |
| `-Connect` | `switch` | Connect to Microsoft Graph before running. |

### `Get-EntraComplianceReport`

Runs checks and returns a report object without connecting.

### `Test-EntraSecurityDefaults`

Returns a single `ComplianceResult` for the Security Defaults policy.

### `Test-EntraConditionalAccess`

Returns an array of `ComplianceResult` objects covering legacy-auth blocking and MFA enforcement policies.

### `Test-EntraMFAPolicy`

Returns a `ComplianceResult` for the Authentication Methods policy.

### `Test-EntraPasswordPolicy`

Returns a `ComplianceResult` for the organisation's password validity period.

---

## Compliance Rules Configuration

Edit `EntraComplianceAuditor/config/compliance-rules.yaml` to customise thresholds:

```yaml
ConditionalAccess:
  BlockLegacyAuthentication: true
  RequireMFAForAdmins: true
  RequireMFAForAllUsers: false   # set to true to enforce for all users

PasswordPolicy:
  MaxPasswordAgeDays: 90
```

Pass the path to a custom file via `-RulesPath` if you keep it outside the module directory.

---

## Running Tests

[Pester](https://pester.dev/) 5.x is required.

```powershell
Install-Module Pester -MinimumVersion 5.0.0 -Scope CurrentUser -Force
Invoke-Pester -Path './tests/EntraComplianceAuditor.Tests.ps1' -Output Detailed
```

The tests stub all Microsoft Graph and `ConvertFrom-Yaml` calls so no live Entra ID tenant is needed.

---

## Output Schema

```
ComplianceReport
├── GeneratedAt       (ISO 8601 string)
├── TenantId          (string)
├── ComplianceScore   (0–100 float)
├── Summary
│   ├── Total / Pass / Fail / Warning / Error  (int)
└── Results[]
    ├── CheckName      (string)
    ├── Category       (string)
    ├── Status         (Pass | Fail | Warning | NotApplicable | Error)
    ├── Description    (string)
    ├── Recommendation (string)
    ├── Details        (hashtable | null)
    ├── Severity       (Critical | High | Medium | Low | Informational)
    └── Timestamp      (ISO 8601 string)
```