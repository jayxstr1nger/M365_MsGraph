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

# --- Directory role classes ---

class RoleActiveAssignmentItem {
    [string]$UserId
    [string]$UserPrincipalName
    [string]$RoleDisplayName
    [string]$DirectoryScope
    [Microsoft.Graph.Beta.PowerShell.Models.IMicrosoftGraphUnifiedRoleAssignmentSchedule]$ScheduleInstance

    RoleActiveAssignmentItem([Microsoft.Graph.PowerShell.Models.IMicrosoftGraphUser]$_user, [Microsoft.Graph.Beta.PowerShell.Models.IMicrosoftGraphUnifiedRoleAssignmentSchedule]$_scheduleInstance) {
        $this.UserId = $_user.Id
        $this.UserPrincipalName = $_user.UserPrincipalName
        $this.RoleDisplayName = $_scheduleInstance.RoleDefinition.DisplayName
        $this.DirectoryScope = $_scheduleInstance.DirectoryScopeId
        $this.ScheduleInstance = $_scheduleInstance
    }

    [string] ToString() {
        return "$($this.RoleDisplayName) -> $($this.DirectoryScope)"
    }
}

class RoleEligibleAssignmentItem {
    [string]$UserId
    [string]$UserPrincipalName
    [string]$RoleDisplayName
    [string]$DirectoryScope
    [Microsoft.Graph.Beta.PowerShell.Models.IMicrosoftGraphUnifiedRoleEligibilitySchedule]$ScheduleInstance

    RoleEligibleAssignmentItem([Microsoft.Graph.PowerShell.Models.IMicrosoftGraphUser]$_user, [Microsoft.Graph.Beta.PowerShell.Models.IMicrosoftGraphUnifiedRoleEligibilitySchedule]$_scheduleInstance) {
        $this.UserId = $_user.Id
        $this.UserPrincipalName = $_user.UserPrincipalName
        $this.RoleDisplayName = $_scheduleInstance.RoleDefinition.DisplayName
        $this.DirectoryScope = $_scheduleInstance.DirectoryScopeId
        $this.ScheduleInstance = $_scheduleInstance
    }

    [string] ToString() {
        return "$($this.RoleDisplayName) -> $($this.DirectoryScope)"
    }
}

class DirectoryRoleAssignments {
    [System.Collections.Generic.List[RoleActiveAssignmentItem]]$Active
    [System.Collections.Generic.List[RoleEligibleAssignmentItem]]$Eligible

    DirectoryRoleAssignments() {
        $this.Active = [System.Collections.Generic.List[RoleActiveAssignmentItem]]::new()
        $this.Eligible = [System.Collections.Generic.List[RoleEligibleAssignmentItem]]::new()
    }
}

# --- Role assignable group classes ---

class GroupActiveAssignmentItem {
    [string]$UserId
    [string]$UserPrincipalName
    [string]$GroupId
    [string]$GroupDisplayName
    [Microsoft.Graph.Beta.PowerShell.Models.IMicrosoftGraphPrivilegedAccessGroupAssignmentSchedule]$ScheduleInstance

    GroupActiveAssignmentItem([Microsoft.Graph.PowerShell.Models.IMicrosoftGraphUser]$_user, [Microsoft.Graph.PowerShell.Models.IMicrosoftGraphGroup]$_group, [Microsoft.Graph.Beta.PowerShell.Models.IMicrosoftGraphPrivilegedAccessGroupAssignmentSchedule]$_scheduleInstance) {
        $this.UserId = $_user.Id
        $this.UserPrincipalName = $_user.UserPrincipalName
        $this.GroupId = $_group.Id
        $this.GroupDisplayName = $_group.DisplayName
        $this.ScheduleInstance = $_scheduleInstance
    }

    [string] ToString() {
        return $this.GroupDisplayName
    }
}

class GroupEligibleAssignmentItem {
    [string]$UserId
    [string]$UserPrincipalName
    [string]$GroupId
    [string]$GroupDisplayName
    [Microsoft.Graph.Beta.PowerShell.Models.IMicrosoftGraphUnifiedRoleEligibilitySchedule]$ScheduleInstance

    GroupEligibleAssignmentItem([Microsoft.Graph.PowerShell.Models.IMicrosoftGraphUser]$_user, [Microsoft.Graph.PowerShell.Models.IMicrosoftGraphGroup]$_group, [Microsoft.Graph.Beta.PowerShell.Models.IMicrosoftGraphPrivilegedAccessGroupEligibilityScheduleInstance]$_scheduleInstance) {
        $this.UserId = $_user.Id
        $this.UserPrincipalName = $_user.UserPrincipalName
        $this.GroupId = $_group.Id
        $this.GroupDisplayName = $_group.DisplayName
        $this.ScheduleInstance = $_scheduleInstance
    }

    [string] ToString() {
        return $this.GroupDisplayName
    }
}

class DirectoryGroupAssignments {
    [System.Collections.Generic.List[GroupActiveAssignmentItem]]$Active
    [System.Collections.Generic.List[GroupEligibleAssignmentItem]]$Eligible

    DirectoryGroupAssignments() {
        $this.Active = [System.Collections.Generic.List[GroupActiveAssignmentItem]]::new()
        $this.Eligible = [System.Collections.Generic.List[GroupEligibleAssignmentItem]]::new()
    }
}

# --- Other classes ---

class UserPrivilegedIdentityManagementAssignments {
    [DirectoryRoleAssignments]$Roles
    [DirectoryGroupAssignments]$Groups

    UserPrivilegedIdentityManagementAssignments() {
        $this.Roles = [DirectoryRoleAssignments]::new()
        $this.Groups = [DirectoryGroupAssignments]::new()
    }
}

# --- Core script logic ---

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
    "RoleEligibilitySchedule.ReadWrite.Directory",
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

$pimAssignments = [UserPrivilegedIdentityManagementAssignments]::new()

# Get active directory role assignments.
Write-Verbose -Message "Fetching active role assignments for '$($user.UserPrincipalName)'"
$activeAssignments = Get-MgBetaRoleManagementDirectoryRoleAssignmentScheduleInstance -Filter "principalId eq '$($user.Id)'" -ExpandProperty @("roleDefinition") -ErrorAction "Stop"

foreach ($assignmentItem in $activeAssignments) {
    if ($assignmentItem.MemberType -ne "Group") {
        $pimAssignments.Roles.Active.Add([RoleActiveAssignmentItem]::new($user, $assignmentItem))
    }
}

# Get eligible directory role assignments.
Write-Verbose -Message "Fetching eligible role assignments for '$($user.UserPrincipalName)'"
$eligibleAssignments = Get-MgBetaRoleManagementDirectoryRoleEligibilityScheduleInstance -Filter "principalId eq '$($user.Id)'" -ExpandProperty @("roleDefinition") -ErrorAction "Stop"

foreach ($assignmentItem in $eligibleAssignments) {
    if ($assignmentItem.MemberType -ne "Group") {
        $pimAssignments.Roles.Eligible.Add([RoleEligibleAssignmentItem]::new($user, $assignmentItem))
    }
}

# Get role assignable groups for the user.
Write-Verbose -Message "Getting all role assignable groups"
$groups = Get-MgGroup -Filter "securityEnabled eq true and isAssignableToRole eq true" -All -Select @("id", "displayName") -ErrorAction "Stop" | Sort-Object -Property "DisplayName"

foreach ($groupItem in $groups) {
    Write-Verbose -Message "Fetching assignments to '$($groupItem.DisplayName)' for '$($user.UserPrincipalName)'."
    
    # Get active role assignments for the group.
    $activeGroupAssignments = Get-MgBetaIdentityGovernancePrivilegedAccessGroupAssignmentScheduleInstance -Filter "groupId eq '$($groupItem.Id)' and principalId eq '$($user.Id)'" -ErrorAction "SilentlyContinue"

    foreach ($assignmentItem in $activeGroupAssignments) {
        $pimAssignments.Groups.Active.Add([GroupActiveAssignmentItem]::new($user, $groupItem, $assignmentItem))
    }

    # Get eligible role assignments for the group.
    $eligibleGroupAssignments = Get-MgBetaIdentityGovernancePrivilegedAccessGroupEligibilityScheduleInstance -Filter "groupId eq '$($groupItem.Id)' and principalId eq '$($user.Id)'" -ErrorAction "SilentlyContinue"

    foreach ($assignmentItem in $eligibleGroupAssignments) {
        $pimAssignments.Groups.Eligible.Add([GroupEligibleAssignmentItem]::new($user, $groupItem, $assignmentItem))
    }
}

# Write the collected data to the output.
Write-Output -InputObject $pimAssignments
