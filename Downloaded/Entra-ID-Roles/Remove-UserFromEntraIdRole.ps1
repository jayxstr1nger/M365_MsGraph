<#PSScriptInfo

.VERSION 1.0.0

.GUID 159c907f-8723-4a0a-85ba-47434cb523a0

.AUTHOR Tim Small

.COMPANYNAME Smalls.Online

.COPYRIGHT 2024

.TAGS entraid pim privileged-identity-management entraid-role

.LICENSEURI https://git.smalls.online/smalls/EntraID.PIM.Scripts/blob/main/LICENSE

.PROJECTURI https://git.smalls.online/smalls/EntraID.PIM.Scripts

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES

#>

#Requires -Module @{ ModuleName = "Microsoft.Graph.Authentication"; ModuleVersion = "2.17.0" }
#Requires -Module @{ ModuleName = "Microsoft.Graph.Groups"; ModuleVersion = "2.17.0" }
#Requires -Module @{ ModuleName = "Microsoft.Graph.Users"; ModuleVersion = "2.17.0" }
#Requires -Module @{ ModuleName = "Microsoft.Graph.Beta.Identity.Governance"; ModuleVersion = "2.17.0" }

<#
.SYNOPSIS
    Remove a user's assignment to an Entra ID role.
.DESCRIPTION
    Remove a user's active or eligible assignment to an Entra ID role.
.PARAMETER UserId
    The ID of the user in Entra ID.
.PARAMETER RoleName
    The name of the directory role. If not provided, it will default to all directory roles.
.EXAMPLE
    Remove-UserFromEntraIdRole.ps1 -UserId "jwinger@greendalecc.edu" -GroupId "User Administrator"

    Removes the user's assignment from the "User Administrator" directory role.
.EXAMPLE
    Remove-UserFromEntraIdRole.ps1 -UserId "jwinger@greendalecc.edu"

    Removes the user's assignment from any directory role.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Position = 0, Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$UserId,
    [Parameter(Position = 1)]
    [string[]]$RoleName
)

class DirectoryRoleAssignments {
    [System.Collections.Generic.List[Microsoft.Graph.Beta.PowerShell.Models.IMicrosoftGraphUnifiedRoleAssignmentSchedule]]$Active
    [System.Collections.Generic.List[Microsoft.Graph.Beta.PowerShell.Models.IMicrosoftGraphUnifiedRoleEligibilitySchedule]]$Eligible

    DirectoryRoleAssignments() {
        $this.Active = [System.Collections.Generic.List[Microsoft.Graph.Beta.PowerShell.Models.IMicrosoftGraphUnifiedRoleAssignmentSchedule]]::new()
        $this.Eligible = [System.Collections.Generic.List[Microsoft.Graph.Beta.PowerShell.Models.IMicrosoftGraphUnifiedRoleEligibilitySchedule]]::new()
    }
}

# Check if the user is authenticated to the Microsoft Graph API.
$mgContext = Get-MgContext

if ($null -eq $mgContext) {
    $PSCmdlet.ThrowTerminatingError(
        [System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new("Please run 'Connect-MgGraph' first before running."),
            "NotAuthenticatedToGraph",
            [System.Management.Automation.ErrorCategory]::AuthenticationError,
            $null
        )
    )
}

# Check if the required scopes are present
# for the Microsoft Graph API.
$requiredGraphScopes = @(
    "User.Read.All",
    "RoleManagement.Read.Directory",
    "RoleAssignmentSchedule.ReadWrite.Directory",
    "RoleEligibilitySchedule.ReadWrite.Directory"
)

$missingScopes = $requiredGraphScopes | Where-Object { $PSItem -notin $mgContext.Scopes }

if ($null -ne $missingScopes) {
    $PSCmdlet.ThrowTerminatingError(
        [System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new("Please run 'Connect-MgGraph' with the required scopes: $($missingScopes -join ', ')"),
            "NotAuthenticatedToGraph",
            [System.Management.Automation.ErrorCategory]::AuthenticationError,
            $missingScopes
        )
    )
}

# Get the user.
$user = $null
try {
    $user = Get-MgUser -UserId $UserId -ErrorAction "Stop"
}
catch [System.Exception] {
    $ex = $PSItem.Exception

    $PSCmdlet.ThrowTerminatingError(
        [System.Management.Automation.ErrorRecord]::new(
            $ex,
            "GetUserFailed",
            [System.Management.Automation.ErrorCategory]::InvalidResult,
            $null
        )
    )
}

# Get the role to remove the user from.
$directoryRoles = $null
if ($null -eq $RoleName -or [string]::IsNullOrEmpty($RoleName)) {
    Write-Verbose "No 'RoleName' provided, fetching all directory roles."
    $directoryRoles = Get-MgBetaRoleManagementDirectoryRoleDefinition -All | Sort-Object -Property "DisplayName"
}
else {
    $directoryRoles = foreach ($roleNameItem in $RoleName) {
        Write-Verbose "Fetching directory role '$($roleNameItem)'."
        $fetchedDirectoryRole = Get-MgBetaRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$($roleNameItem)'"

        if ($null -eq $fetchedDirectoryRole) {
            Write-Warning "Directory role '$($roleNameItem)' not found."
            continue
        }

        $fetchedDirectoryRole
    }
}

if ($null -eq $directoryRoles) {
    $PSCmdlet.ThrowTerminatingError(
        [System.Management.Automation.ErrorRecord]::new(
            [System.Exception]::new("Failed to get directory roles."),
            "GetRoleFailed",
            [System.Management.Automation.ErrorCategory]::InvalidResult,
            $null
        )
    )
}

# Get the role assignments for the user.
$roleAssignments = [DirectoryRoleAssignments]::new()

foreach ($directoryRole in $directoryRoles) {
    Write-Verbose "Fetching role assignments to '$($directoryRole.DisplayName)' for '$($user.UserPrincipalName)'."
    
    # Get active assignments for the directory role.
    $activeAssignments = Get-MgBetaRoleManagementDirectoryRoleAssignmentSchedule -Filter "roleDefinitionId eq '$($directoryRole.Id)' and principalId eq '$($user.Id)'" -ExpandProperty "roleDefinition" -ErrorAction "SilentlyContinue"

    foreach ($activeAssignment in $activeAssignments) {
        $roleAssignments.Active.Add($activeAssignment)
    }

    # Get eligible assignments for the directory role.
    $eligibleAssignments = Get-MgBetaRoleManagementDirectoryRoleEligibilitySchedule -Filter "roleDefinitionId eq '$($directoryRole.Id)' and principalId eq '$($user.Id)'" -ExpandProperty "roleDefinition" -ErrorAction "SilentlyContinue"

    foreach ($eligibleAssignment in $eligibleAssignments) {
        $roleAssignments.Eligible.Add($eligibleAssignment)
    }
}

# If no role assignments are found, do nothing and return.
if ($roleAssignments.Active.Count -eq 0 -and $roleAssignments.Eligible.Count -eq 0) {
    Write-Warning "No role assignments found for the user '$($user.UserPrincipalName)'."
    return
}

# Remove active role assignments.
foreach ($roleAssignmentItem in $roleAssignments.Active) {
    if ($PSCmdlet.ShouldProcess($roleAssignmentItem.RoleDefinition.DisplayName, "Remove active role assignment for $($user.UserPrincipalName)")) {
        New-MgBetaRoleManagementDirectoryRoleAssignmentScheduleRequest -PrincipalId $user.Id -RoleDefinitionId $roleAssignmentItem.RoleDefinitionId -Action "AdminRemove" -DirectoryScopeId $roleAssignmentItem.DirectoryScopeId
    }
}

# Remove eligible role assignments.
foreach ($roleAssignmentItem in $roleAssignments.Eligible) {
    if ($PSCmdlet.ShouldProcess($roleAssignmentItem.RoleDefinition.DisplayName, "Remove eligible role assignment for $($user.UserPrincipalName)")) {
        New-MgBetaRoleManagementDirectoryRoleEligibilityScheduleRequest -PrincipalId $user.Id -RoleDefinitionId $roleAssignmentItem.RoleDefinitionId -Action "AdminRemove" -DirectoryScopeId $roleAssignmentItem.DirectoryScopeId
    }
}
