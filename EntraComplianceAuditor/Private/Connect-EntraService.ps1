function Connect-EntraService {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph with the scopes required for compliance auditing.
    .PARAMETER TenantId
        Optional. The Entra ID tenant to connect to.
    .PARAMETER Scopes
        Microsoft Graph permission scopes to request.
    #>
    [CmdletBinding()]
    param (
        [string]$TenantId,

        [string[]]$Scopes = @(
            'Policy.Read.All',
            'Directory.Read.All',
            'UserAuthenticationMethod.Read.All'
        )
    )

    if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
        throw "The 'Microsoft.Graph.Authentication' module is required. " +
              "Install it with: Install-Module -Name Microsoft.Graph -Scope CurrentUser"
    }

    Import-Module -Name Microsoft.Graph.Authentication -ErrorAction Stop

    $connectParams = @{ Scopes = $Scopes }
    if ($TenantId) {
        $connectParams['TenantId'] = $TenantId
    }

    Connect-MgGraph @connectParams
}
