<#PSScriptInfo

.VERSION 1.0.0

.GUID d8eb6328-a330-4b35-8185-c8f42faf4f4b

.AUTHOR Tim Small

.COMPANYNAME Smalls.Online

.COPYRIGHT 2024

.TAGS entraid pim privileged-identity-management privileged-access-groups

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
    Remove a user from a Privileged Access Group.
.DESCRIPTION
    Remove a user from a Privileged Access Group(s) in Entra ID.
.PARAMETER UserId
    The ID of the user in Entra ID.
.PARAMETER GroupId
    The ID of the group in Entra ID. If not provided, all groups that are assignable to a role will be fetched.
.PARAMETER RoleType
    The role type to remove the user from.
.EXAMPLE
    Remove-UserFromPrivilegedAccessGroup.ps1 -UserId "jwinger@greendalecc.edu" -GroupId "00000000-0000-0000-0000-000000000000"

    Removes the user's "member" role from the group with the ID "00000000-0000-0000-0000-000000000000".
.EXAMPLE
    Remove-UserFromPrivilegedAccessGroup.ps1 -UserId "jwinger@greendalecc.edu"

    Removes the user's "member" role from any group that is assignable to a role.
.EXAMPLE
    Remove-UserFromPrivilegedAccessGroup.ps1 -UserId "jwinger@greendalecc.edu" -GroupId "00000000-0000-0000-0000-000000000000" -RoleType "owner"

    Removes the user's "owner" role from the group with the ID "00000000-0000-0000-0000-000000000000".
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Position = 0, Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$UserId,
    [Parameter(Position = 1)]
    [string[]]$GroupId,
    [Parameter(Position = 2)]
    [ValidateSet("member", "owner")]
    [string]$RoleType = "member"
)

class PrivilegedAccessGroupAssignments {
    [System.Collections.Generic.List[object]]$Active
    [System.Collections.Generic.List[object]]$Eligible

    PrivilegedAccessGroupAssignments() {
        $this.Active = [System.Collections.Generic.List[object]]::new()
        $this.Eligible = [System.Collections.Generic.List[object]]::new()
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
    "Group.Read.All",
    "PrivilegedAccess.ReadWrite.AzureADGroup"
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

# Get the group(s) to remove the user from.
$groups = $null
try {
    if ($null -eq $GroupId -or [string]::IsNullOrEmpty($GroupId)) {
        # Fetch all groups that are assignable to a role if no 'GroupId' is provided.

        Write-Verbose "No 'GroupId' provided, fetching all groups that are assignable to a role."
        $groups = Get-MgGroup -Filter "securityEnabled eq true and isAssignableToRole eq true" -All -ErrorAction "Stop" | Sort-Object -Property "DisplayName"
    }
    else {
        # Fetch the group with the provided 'GroupId'.

        $groups = foreach ($groupIdItem in $GroupId) {
            Write-Verbose "Fetching group '$($groupIdItem)'."

            $fetchedGroup = Get-MgGroup -GroupId $groupIdItem -ErrorAction "SilentlyContinue"

            if ($null -eq $fetchedGroup) {
                Write-Warning "Group with the ID '$($groupIdItem)' not found."
                continue
            }

            $fetchedGroup
        }
    }
}
catch [System.Exception] {
    $ex = $PSItem.Exception

    $PSCmdlet.ThrowTerminatingError(
        [System.Management.Automation.ErrorRecord]::new(
            $ex,
            "GetGroupFailed",
            [System.Management.Automation.ErrorCategory]::InvalidResult,
            $null
        )
    )
}

# Get the role assignments for the user.
$roleAssignments = [PrivilegedAccessGroupAssignments]::new()

foreach ($groupItem in $groups) {
    Write-Verbose "Fetching role assignments to '$($groupItem.DisplayName)' for '$($user.UserPrincipalName)'."
    
    # Get active role assignments for the group.
    $activeAssignments = Get-MgBetaIdentityGovernancePrivilegedAccessGroupAssignmentSchedule -Filter "groupId eq '$($groupItem.Id)' and principalId eq '$($user.Id)'" -ErrorAction "SilentlyContinue"

    foreach ($activeAssignment in $activeAssignments) {
        $roleAssignments.Active.Add($activeAssignment)
    }

    # Get eligible role assignments for the group.
    $eligibleAssignments = Get-MgBetaIdentityGovernancePrivilegedAccessGroupEligibilitySchedule -Filter "groupId eq '$($groupItem.Id)' and principalId eq '$($user.Id)'" -ErrorAction "SilentlyContinue"

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
    if ($PSCmdlet.ShouldProcess($roleAssignmentItem.GroupId, "Remove active role assignment for $($user.UserPrincipalName)")) {
        New-MgBetaIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -PrincipalId $user.Id -GroupId $roleAssignmentItem.GroupId -AccessId $RoleType -Action "adminRemove"
    }
}

# Remove eligible role assignments.
foreach ($roleAssignmentItem in $roleAssignments.Eligible) {
    if ($PSCmdlet.ShouldProcess($roleAssignmentItem.GroupId, "Remove eligible role assignment for $($user.UserPrincipalName)")) {
        New-MgBetaIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -PrincipalId $user.Id -GroupId $roleAssignmentItem.GroupId -AccessId $RoleType -Action "adminRemove"
    }
}
