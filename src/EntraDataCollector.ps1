#Requires -Version 5.1
<#
.SYNOPSIS
    Entra Data Collector - Fetches Entra ID objects via the Microsoft Graph PowerShell SDK.

.DESCRIPTION
    This module is responsible for:
      - Verifying that the Microsoft.Graph.* modules are available and that an active
        Graph session exists (Connect-MgGraph must have been called by the caller).
      - Fetching Entra ID objects for each supported target type.
      - Applying optional server-side OData filters when the rule specifies one.
      - Returning normalised PSCustomObjects that can be evaluated by the Evaluator.
      - Handling API throttling (HTTP 429) with automatic exponential-backoff retries.

.NOTES
    Part of the Entra ID Compliance Auditor toolkit.
    Prerequisites:
      - Microsoft.Graph.Users
      - Microsoft.Graph.Groups
      - Microsoft.Graph.Applications
      - Microsoft.Graph.Identity.DirectoryManagement
#>

Set-StrictMode -Version Latest

#region ── Module Guard ───────────────────────────────────────────────────────

function Assert-GraphConnection {
    <#
    .SYNOPSIS
        Throws if there is no active Microsoft Graph session.
    #>
    [CmdletBinding()]
    param()

    try {
        $ctx = Get-MgContext -ErrorAction Stop
        if ($null -eq $ctx) {
            throw 'No Microsoft Graph context found.'
        }
    }
    catch {
        throw ("No active Microsoft Graph session detected. " +
            "Please run Connect-MgGraph before invoking the compliance check. Error: $_")
    }
}

function Assert-GraphModules {
    <#
    .SYNOPSIS
        Warns if required Microsoft.Graph sub-modules are not imported.
    #>
    [CmdletBinding()]
    param()

    $required = @(
        'Microsoft.Graph.Users',
        'Microsoft.Graph.Groups',
        'Microsoft.Graph.Applications',
        'Microsoft.Graph.Identity.DirectoryManagement'
    )

    foreach ($mod in $required) {
        if (-not (Get-Module -Name $mod -ErrorAction SilentlyContinue)) {
            Write-Warning "Module '$mod' is not imported. Some data collection steps may fail."
        }
    }
}

#endregion

#region ── Throttle-Safe Invoke Helper ────────────────────────────────────────

function Invoke-GraphWithRetry {
    <#
    .SYNOPSIS
        Executes a scriptblock that calls a Mg* command and retries on throttling (HTTP 429).
    .PARAMETER ScriptBlock
        The scriptblock to execute (should return Graph objects).
    .PARAMETER MaxRetries
        Maximum number of retry attempts (default 5).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [int]$MaxRetries = 5
    )

    $attempt    = 0
    $delaySecs  = 2

    while ($true) {
        try {
            return & $ScriptBlock
        }
        catch {
            $errMsg = $_.Exception.Message
            $is429  = $errMsg -match '429|TooManyRequests|throttl'

            if ($is429 -and $attempt -lt $MaxRetries) {
                $attempt++
                Write-Warning ("Graph API throttle detected (attempt $attempt/$MaxRetries). " +
                    "Retrying in $delaySecs seconds...")
                Start-Sleep -Seconds $delaySecs
                $delaySecs = $delaySecs * 2   # exponential back-off
            }
            else {
                throw $_
            }
        }
    }
}

#endregion

#region ── Target Collectors ──────────────────────────────────────────────────

function Get-EntraUsers {
    <#
    .SYNOPSIS
        Fetches user objects from Microsoft Graph.
    .PARAMETER Filter
        Optional OData filter string.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [string]$Filter = ''
    )

    Write-Verbose "Fetching Users from Graph..."

    $params = @{
        All              = $true
        Property         = @(
            'Id', 'DisplayName', 'UserPrincipalName', 'AccountEnabled',
            'UserType', 'StrongAuthenticationMethods', 'AccountExpires',
            'CreatedDateTime', 'AssignedLicenses'
        )
        ErrorAction      = 'Stop'
    }
    if ($Filter) { $params['Filter'] = $Filter }

    $users = Invoke-GraphWithRetry -ScriptBlock {
        Get-MgUser @params
    }

    return $users | ForEach-Object {
        [PSCustomObject]@{
            ObjectId                   = $_.Id
            DisplayName                = $_.DisplayName
            UserPrincipalName          = $_.UserPrincipalName
            AccountEnabled             = $_.AccountEnabled
            UserType                   = $_.UserType
            StrongAuthenticationMethods = $_.StrongAuthenticationMethods
            AccountExpires             = $_.AdditionalProperties['accountExpires']
            CreatedDateTime            = $_.CreatedDateTime
            AssignedLicenses           = $_.AssignedLicenses
        }
    }
}

function Get-EntraGroups {
    <#
    .SYNOPSIS
        Fetches group objects (with owner metadata) from Microsoft Graph.
    .PARAMETER Filter
        Optional OData filter string.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [string]$Filter = ''
    )

    Write-Verbose "Fetching Groups from Graph..."

    $params = @{
        All         = $true
        Property    = @(
            'Id', 'DisplayName', 'GroupTypes', 'MembershipRule',
            'SecurityEnabled', 'MailEnabled', 'Description'
        )
        ErrorAction = 'Stop'
    }
    if ($Filter) { $params['Filter'] = $Filter }

    $groups = Invoke-GraphWithRetry -ScriptBlock {
        Get-MgGroup @params
    }

    return $groups | ForEach-Object {
        $group = $_
        # Fetch owners count (separate call)
        try {
            $owners = Invoke-GraphWithRetry -ScriptBlock {
                Get-MgGroupOwner -GroupId $group.Id -ErrorAction Stop
            }
        }
        catch {
            Write-Warning "Could not fetch owners for group '$($group.DisplayName)': $_"
            $owners = @()
        }

        [PSCustomObject]@{
            ObjectId        = $group.Id
            DisplayName     = $group.DisplayName
            GroupTypes      = $group.GroupTypes
            MembershipRule  = $group.MembershipRule
            SecurityEnabled = $group.SecurityEnabled
            MailEnabled     = $group.MailEnabled
            Description     = $group.Description
            Owners          = $owners
        }
    }
}

function Get-EntraEnterpriseApplications {
    <#
    .SYNOPSIS
        Fetches service principal (enterprise application) objects from Microsoft Graph.
    .PARAMETER Filter
        Optional OData filter string.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [string]$Filter = ''
    )

    Write-Verbose "Fetching Enterprise Applications (Service Principals) from Graph..."

    $params = @{
        All         = $true
        Property    = @(
            'Id', 'DisplayName', 'AppId', 'Notes',
            'Tags', 'KeyCredentials', 'PasswordCredentials',
            'RequiredResourceAccess', 'PreferredSingleSignOnMode',
            'AccountEnabled', 'AppRoles'
        )
        ErrorAction = 'Stop'
    }
    if ($Filter) { $params['Filter'] = $Filter }

    $sps = Invoke-GraphWithRetry -ScriptBlock {
        Get-MgServicePrincipal @params
    }

    return $sps | ForEach-Object {
        $sp = $_
        # IsVisibleInLaunchpad: a service principal is visible when it has the
        # 'HideApp' tag absent and the 'WindowsAzureActiveDirectoryIntegratedApp' tag present.
        $tags             = if ($null -ne $sp.Tags) { $sp.Tags } else { @() }
        $isVisible        = ($tags -contains 'WindowsAzureActiveDirectoryIntegratedApp') -and
                            ($tags -notcontains 'HideApp')

        [PSCustomObject]@{
            ObjectId               = $sp.Id
            DisplayName            = $sp.DisplayName
            AppId                  = $sp.AppId
            Notes                  = $sp.Notes
            Tags                   = $tags
            KeyCredentials         = $sp.KeyCredentials
            PasswordCredentials    = $sp.PasswordCredentials
            RequiredResourceAccess = $sp.RequiredResourceAccess
            IsVisibleInLaunchpad   = $isVisible
            AccountEnabled         = $sp.AccountEnabled
            AppRoles               = $sp.AppRoles
        }
    }
}

function Get-EntraAppRoleAssignments {
    <#
    .SYNOPSIS
        Fetches app role assignments across all service principals.
    .PARAMETER Filter
        Unused (included for API consistency; filtering is done client-side).
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [string]$Filter = ''
    )

    Write-Verbose "Fetching App Role Assignments from Graph..."

    # Collect all service principals first, then get their app role assignments
    $sps = Invoke-GraphWithRetry -ScriptBlock {
        Get-MgServicePrincipal -All -ErrorAction Stop
    }

    $assignments = @()
    foreach ($sp in $sps) {
        try {
            $spAssignments = Invoke-GraphWithRetry -ScriptBlock {
                Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id -All -ErrorAction Stop
            }
            foreach ($a in $spAssignments) {
                $assignments += [PSCustomObject]@{
                    ObjectId            = $a.Id
                    DisplayName         = "$($a.PrincipalDisplayName) -> $($sp.DisplayName)"
                    ResourceId          = $a.ResourceId
                    ResourceDisplayName = $a.ResourceDisplayName
                    PrincipalId         = $a.PrincipalId
                    PrincipalDisplayName = $a.PrincipalDisplayName
                    PrincipalType       = $a.PrincipalType
                    AppRoleId           = $a.AppRoleId
                    CreatedDateTime     = $a.CreatedDateTime
                }
            }
        }
        catch {
            Write-Warning "Could not fetch app role assignments for '$($sp.DisplayName)': $_"
        }
    }

    return $assignments
}

function Get-EntraDirectoryRoles {
    <#
    .SYNOPSIS
        Fetches activated directory roles with their member counts.
    .PARAMETER Filter
        Optional OData filter string applied to role display names.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [string]$Filter = ''
    )

    Write-Verbose "Fetching Directory Roles from Graph..."

    $params = @{
        All         = $true
        ErrorAction = 'Stop'
    }
    if ($Filter) { $params['Filter'] = $Filter }

    $roles = Invoke-GraphWithRetry -ScriptBlock {
        Get-MgDirectoryRole @params
    }

    return $roles | ForEach-Object {
        $role = $_
        try {
            $members = Invoke-GraphWithRetry -ScriptBlock {
                Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction Stop
            }
            $memberCount = $members.Count
        }
        catch {
            Write-Warning "Could not fetch members for role '$($role.DisplayName)': $_"
            $memberCount = 0
        }

        [PSCustomObject]@{
            ObjectId     = $role.Id
            DisplayName  = $role.DisplayName
            Description  = $role.Description
            RoleTemplateId = $role.RoleTemplateId
            MemberCount  = $memberCount
        }
    }
}

#endregion

#region ── Public API ─────────────────────────────────────────────────────────

function Get-EntraObjects {
    <#
    .SYNOPSIS
        Dispatches to the appropriate collector based on the rule target type.
    .PARAMETER Target
        The target type string from the rule (e.g. 'Users', 'Groups').
    .PARAMETER Filter
        Optional OData filter string to pass to the Graph query.
    .OUTPUTS
        [PSCustomObject[]] Normalised objects ready for condition evaluation.
    .EXAMPLE
        $objects = Get-EntraObjects -Target 'EnterpriseApplications'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Users', 'Groups', 'EnterpriseApplications', 'AppRoleAssignments', 'DirectoryRoles')]
        [string]$Target,

        [string]$Filter = ''
    )

    Assert-GraphConnection
    Assert-GraphModules

    switch ($Target) {
        'Users'                  { return Get-EntraUsers                  -Filter $Filter }
        'Groups'                 { return Get-EntraGroups                 -Filter $Filter }
        'EnterpriseApplications' { return Get-EntraEnterpriseApplications -Filter $Filter }
        'AppRoleAssignments'     { return Get-EntraAppRoleAssignments     -Filter $Filter }
        'DirectoryRoles'         { return Get-EntraDirectoryRoles         -Filter $Filter }
        default                  { throw "Unsupported target: '$Target'" }
    }
}

#endregion
