#Requires -Version 5.1
<#
.SYNOPSIS
    Report Generator - Produces HTML and summary reports from compliance violations.

.DESCRIPTION
    This module is responsible for:
      - Generating a styled, self-contained HTML report from violation records.
      - Producing a console-friendly summary table (compliant vs. non-compliant).
      - Writing the HTML report to disk.

.NOTES
    Part of the Entra ID Compliance Auditor toolkit.
#>

Set-StrictMode -Version Latest

#region ── HTML Report ────────────────────────────────────────────────────────

function Get-HtmlHeader {
    [OutputType([string])]
    param(
        [string]$Title,
        [string]$GeneratedAt
    )

    return @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>$Title</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: #f3f4f6;
      color: #1f2937;
      padding: 2rem;
    }
    header {
      background: linear-gradient(135deg, #0f4c81, #1976d2);
      color: white;
      padding: 2rem;
      border-radius: 12px;
      margin-bottom: 2rem;
      box-shadow: 0 4px 12px rgba(0,0,0,.15);
    }
    header h1 { font-size: 1.8rem; }
    header p  { margin-top: .4rem; font-size: .9rem; opacity: .85; }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .card {
      background: white;
      border-radius: 10px;
      padding: 1.2rem 1.5rem;
      box-shadow: 0 2px 6px rgba(0,0,0,.08);
      text-align: center;
    }
    .card .label { font-size: .75rem; text-transform: uppercase; letter-spacing: .08em; color: #6b7280; }
    .card .value { font-size: 2rem; font-weight: 700; margin-top: .3rem; }
    .card.ok    .value { color: #16a34a; }
    .card.warn  .value { color: #d97706; }
    .card.error .value { color: #dc2626; }
    .card.info  .value { color: #2563eb; }
    .section-title {
      font-size: 1.1rem;
      font-weight: 600;
      margin-bottom: .8rem;
      color: #111827;
    }
    .violations-wrapper { overflow-x: auto; margin-bottom: 2rem; }
    table {
      width: 100%;
      border-collapse: collapse;
      background: white;
      border-radius: 10px;
      overflow: hidden;
      box-shadow: 0 2px 6px rgba(0,0,0,.08);
    }
    thead { background: #1976d2; color: white; }
    thead th { padding: .75rem 1rem; text-align: left; font-size: .82rem; font-weight: 600; }
    tbody tr:nth-child(even) { background: #f9fafb; }
    tbody tr:hover { background: #eff6ff; }
    tbody td { padding: .65rem 1rem; font-size: .82rem; border-bottom: 1px solid #e5e7eb; vertical-align: top; }
    .badge {
      display: inline-block;
      border-radius: 9999px;
      padding: .18rem .65rem;
      font-size: .72rem;
      font-weight: 600;
    }
    .badge-violation { background: #fee2e2; color: #991b1b; }
    .badge-compliant { background: #dcfce7; color: #166534; }
    .no-violations {
      background: white;
      border-radius: 10px;
      padding: 2rem;
      text-align: center;
      color: #16a34a;
      font-size: 1.1rem;
      box-shadow: 0 2px 6px rgba(0,0,0,.08);
    }
    footer {
      margin-top: 2rem;
      text-align: center;
      font-size: .78rem;
      color: #9ca3af;
    }
  </style>
</head>
<body>
<header>
  <h1>&#x1F512; Entra ID Compliance Report</h1>
  <p>Generated: $GeneratedAt</p>
</header>
"@
}

function Get-HtmlFooter {
    [OutputType([string])]
    param()
    return @'
<footer>
  <p>Entra ID Compliance Auditor &mdash; Powered by Microsoft Graph PowerShell SDK</p>
</footer>
</body>
</html>
'@
}

function ConvertTo-HtmlReport {
    <#
    .SYNOPSIS
        Converts violation records and a summary object into a self-contained HTML string.
    .PARAMETER Violations
        Array of violation PSCustomObjects (RuleName, ObjectType, ObjectId, DisplayName, ViolationReason).
    .PARAMETER Summary
        PSCustomObject with TotalRules, TotalObjects, ViolatingObjects, CompliantObjects counts.
    .PARAMETER Title
        Report title string.
    .OUTPUTS
        [string] Full HTML content.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Violations,

        [Parameter(Mandatory)]
        [PSCustomObject]$Summary,

        [string]$Title = 'Entra ID Compliance Report'
    )

    $generatedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC')
    $html        = [System.Text.StringBuilder]::new()

    [void]$html.AppendLine((Get-HtmlHeader -Title $Title -GeneratedAt $generatedAt))

    # ── Summary cards ──
    [void]$html.AppendLine('<div class="summary-grid">')
    [void]$html.AppendLine("  <div class='card info'><div class='label'>Rules Evaluated</div><div class='value'>$($Summary.TotalRules)</div></div>")
    [void]$html.AppendLine("  <div class='card info'><div class='label'>Objects Checked</div><div class='value'>$($Summary.TotalObjects)</div></div>")
    [void]$html.AppendLine("  <div class='card ok'><div class='label'>Compliant Objects</div><div class='value'>$($Summary.CompliantObjects)</div></div>")
    [void]$html.AppendLine("  <div class='card error'><div class='label'>Violations</div><div class='value'>$($Summary.ViolatingObjects)</div></div>")
    [void]$html.AppendLine('</div>')

    # ── Violations table ──
    [void]$html.AppendLine('<p class="section-title">Violation Details</p>')

    if ($Violations.Count -eq 0) {
        [void]$html.AppendLine('<div class="no-violations">&#x2705; No violations detected across all evaluated rules.</div>')
    }
    else {
        [void]$html.AppendLine('<div class="violations-wrapper"><table>')
        [void]$html.AppendLine('<thead><tr><th>Rule Name</th><th>Object Type</th><th>Object ID</th><th>Display Name</th><th>Violation Reason</th></tr></thead>')
        [void]$html.AppendLine('<tbody>')

        foreach ($v in $Violations) {
            $ruleNameEncoded   = [System.Web.HttpUtility]::HtmlEncode($v.RuleName)
            $objectTypeEncoded = [System.Web.HttpUtility]::HtmlEncode($v.ObjectType)
            $objectIdEncoded   = [System.Web.HttpUtility]::HtmlEncode($v.ObjectId)
            $displayNameEncoded = [System.Web.HttpUtility]::HtmlEncode($v.DisplayName)
            $reasonEncoded     = [System.Web.HttpUtility]::HtmlEncode($v.ViolationReason)

            [void]$html.AppendLine("<tr>")
            [void]$html.AppendLine("  <td><span class='badge badge-violation'>$ruleNameEncoded</span></td>")
            [void]$html.AppendLine("  <td>$objectTypeEncoded</td>")
            [void]$html.AppendLine("  <td><code>$objectIdEncoded</code></td>")
            [void]$html.AppendLine("  <td>$displayNameEncoded</td>")
            [void]$html.AppendLine("  <td>$reasonEncoded</td>")
            [void]$html.AppendLine("</tr>")
        }

        [void]$html.AppendLine('</tbody></table></div>')
    }

    [void]$html.AppendLine((Get-HtmlFooter))
    return $html.ToString()
}

#endregion

#region ── Console Summary ────────────────────────────────────────────────────

function Write-ComplianceSummary {
    <#
    .SYNOPSIS
        Writes a formatted compliance summary to the console.
    .PARAMETER Summary
        PSCustomObject with TotalRules, TotalObjects, ViolatingObjects, CompliantObjects.
    .PARAMETER Violations
        Array of violation records to display in a table.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Summary,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Violations
    )

    Write-Host ''
    Write-Host '═══════════════════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host '  Entra ID Compliance Check — Summary' -ForegroundColor Cyan
    Write-Host '═══════════════════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host "  Rules Evaluated   : $($Summary.TotalRules)"
    Write-Host "  Objects Checked   : $($Summary.TotalObjects)"
    Write-Host "  Compliant Objects : $($Summary.CompliantObjects)" -ForegroundColor Green
    Write-Host "  Violations Found  : $($Summary.ViolatingObjects)" -ForegroundColor $(if ($Summary.ViolatingObjects -gt 0) { 'Red' } else { 'Green' })
    Write-Host '═══════════════════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host ''

    if ($Violations.Count -gt 0) {
        $Violations | Format-Table -AutoSize -Property RuleName, ObjectType, ObjectId, DisplayName, ViolationReason | Out-Host
    }
    else {
        Write-Host '  ✅  No violations detected.' -ForegroundColor Green
        Write-Host ''
    }
}

#endregion

#region ── Public API ─────────────────────────────────────────────────────────

function Export-ComplianceReport {
    <#
    .SYNOPSIS
        Exports a compliance HTML report to a file and/or writes a summary to the console.
    .PARAMETER Violations
        Array of violation PSCustomObjects.
    .PARAMETER Summary
        Summary statistics object.
    .PARAMETER OutputPath
        If specified, the HTML report is written to this path.
    .PARAMETER ShowSummary
        If $true (default), write a summary table to the console.
    .PARAMETER Title
        Report title (optional).
    .OUTPUTS
        [string] The HTML report content (also written to file if OutputPath provided).
    .EXAMPLE
        Export-ComplianceReport -Violations $violations -Summary $summary -OutputPath './report.html'
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Violations,

        [Parameter(Mandatory)]
        [PSCustomObject]$Summary,

        [string]$OutputPath = '',

        [bool]$ShowSummary = $true,

        [string]$Title = 'Entra ID Compliance Report'
    )

    # Load System.Web for HtmlEncode
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    $htmlContent = ConvertTo-HtmlReport -Violations $Violations -Summary $Summary -Title $Title

    if ($OutputPath) {
        try {
            $htmlContent | Set-Content -Path $OutputPath -Encoding UTF8 -ErrorAction Stop
            Write-Host "HTML report written to: $OutputPath" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to write HTML report to '$OutputPath': $_"
        }
    }

    if ($ShowSummary) {
        Write-ComplianceSummary -Summary $Summary -Violations $Violations
    }

    return $htmlContent
}

#endregion
