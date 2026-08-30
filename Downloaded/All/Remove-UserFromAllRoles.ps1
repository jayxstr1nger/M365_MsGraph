#Requires -Module @{ ModuleName = "Microsoft.Graph.Authentication"; ModuleVersion = "2.30.0" }
#Requires -Module @{ ModuleName = "Microsoft.Graph.Groups"; ModuleVersion = "2.30.0" }
#Requires -Module @{ ModuleName = "Microsoft.Graph.Users"; ModuleVersion = "2.30.0" }
#Requires -Module @{ ModuleName = "Microsoft.Graph.Beta.Identity.Governance"; ModuleVersion = "2.30.0" }
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Position = 0, Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$UserId
)

$getUserRolesScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "Get-UserRoles.ps1"
$pimAssignments = . "$($getUserRolesScriptPath)" -UserId $UserId -ErrorAction "Stop"

# Process directory roles
foreach ($assignmentItem in $pimAssignments.Roles.Active) {
    if ($PSCmdlet.ShouldProcess($assignmentItem.RoleDisplayName, "Remove active role assignment for $($assignmentItem.UserPrincipalName)")) {
        New-MgBetaRoleManagementDirectoryRoleAssignmentScheduleRequest -PrincipalId $assignmentItem.UserId -RoleDefinitionId $assignmentItem.ScheduleInstance.RoleDefinitionId -Action "AdminRemove" -DirectoryScopeId $assignmentItem.DirectoryScope
    }
}

foreach ($assignmentItem in $pimAssignments.Roles.Eligible) {
    if ($PSCmdlet.ShouldProcess($assignmentItem.RoleDisplayName, "Remove eligible role assignment for $($assignmentItem.UserPrincipalName)")) {
        New-MgBetaRoleManagementDirectoryRoleEligibilityScheduleRequest -PrincipalId $assignmentItem.UserId -RoleDefinitionId $assignmentItem.ScheduleInstance.RoleDefinitionId -Action "AdminRemove" -DirectoryScopeId $assignmentItem.DirectoryScope
    }
}

# Process role groups
foreach ($assignmentItem in $pimAssignments.Groups.Active) {
    if ($PSCmdlet.ShouldProcess($assignmentItem.GroupDisplayName, "Remove active role group assignment for $($assignmentItem.UserPrincipalName)")) {
        New-MgBetaIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -PrincipalId $assignmentItem.UserId -GroupId $assignmentItem.GroupId -AccessId $assignmentItem.ScheduleInstance.AccessId -Action "adminRemove"
    }
}

foreach ($assignmentItem in $pimAssignments.Groups.Eligible) {
    if ($PSCmdlet.ShouldProcess($assignmentItem.GroupDisplayName, "Remove eligible role group assignment for $($assignmentItem.UserPrincipalName)")) {
        New-MgBetaIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -PrincipalId $assignmentItem.UserId -GroupId $assignmentItem.GroupId -AccessId $assignmentItem.ScheduleInstance.AccessId -Action "adminRemove"
    }
}
