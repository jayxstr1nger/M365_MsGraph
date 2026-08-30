<#PSScriptInfo

.VERSION 1.0.0

.GUID 297f46a4-d3c8-4a7a-b185-6cd85280a5c8

.AUTHOR Tim Small

.COMPANYNAME Smalls.Online

.COPYRIGHT 2024

.TAGS entraid pim privileged-identity-management privileged-access-groups

.LICENSEURI https://git.smalls.online/smalls/EntraID.PIM.Scripts/raw/branch/main/LICENSE

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
    Add a user to a privileged access group.
.DESCRIPTION
    Add a user to a privileged access group in Entra ID.
.PARAMETER UserId
    The ID or UserPrincipalName of the user in Entra ID.
.PARAMETER GroupId
    The ID of the group in Entra ID.
.PARAMETER GroupName
    The name of the group in Entra ID.
.PARAMETER RoleType
    Whether the user should be assigned as a member or owner of the group.
.PARAMETER StartsOn
    The date and time the assignment will start. Defaults to the start of the current day.
.PARAMETER ExpiresOn
    The date and time the assignment will expire. Defaults to six months from the current date.
.PARAMETER AssignmentType
    Whether the assignment should be active or eligible.
.PARAMETER Justification
    The justification for the assignment.
.INPUTS
    None
.OUTPUTS
    Microsoft.Graph.Beta.PowerShell.Models.MicrosoftGraphPrivilegedAccessGroupAssignmentScheduleRequest
.EXAMPLE
    Add-UserToPrivilegedAccessGroup.ps1 -UserId "jwinger@greendalecc.edu" -GroupId "00000000-0000-0000-0000-000000000000"

    Assigns the user as eligible to the group as a member that starts now and expires in six months.
.EXAMPLE
    Add-UserToPrivilegedAccessGroup.ps1 -UserId "jwinger@greendalecc.edu" -GroupId "00000000-0000-0000-0000-000000000000" -ExpiresOn ([System.DateTimeOffset]::Now.AddMonths(3)) -AssignmentType "Active"

    Assigns the user as active to the group as a member that starts now and expires in three months.
.EXAMPLE
    Add-UserToPrivilegedAccessGroup.ps1 -UserId "jwinger@greendalecc.edu" -GroupName "The Study Group" -RoleType "owner" -StartsOn "2009-09-17 08:00:00 -4:00" -ExpiresOn "2013-05-09 17:00 -4:00" -AssignmentType "Active" -Justification "Jeff is the leader of the group."

    Assigns the user as active to the group as an owner that starts on September 17th, 2009, at 8:00 AM and expires on May 9th, 2013, at 5:00 PM with the justification "Jeff is the leader of the group."
.LINK
    https://git.smalls.online/smalls/EntraID.PIM.Scripts
.LINK
    https://git.smalls.online/smalls/EntraID.PIM.Scripts/blob/main/Scripts/Groups/Add-UserToPrivilegedAccessGroup.ps1
.LINK
    https://git.smalls.online/smalls/EntraID.PIM.Scripts/blob/main/Docs/Groups/Add-UserToPrivilegedAccessGroup.md
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = "GroupId")]
param(
    [Parameter(Position = 0, Mandatory, ParameterSetName = "GroupId")]
    [Parameter(Position = 0, Mandatory, ParameterSetName = "GroupName")]
    [ValidateNotNullOrEmpty()]
    [string]$UserId,
    [Parameter(Position = 1, Mandatory, ParameterSetName = "GroupId")]
    [ValidateNotNullOrEmpty()]
    [string]$GroupId,
    [Parameter(Position = 1, Mandatory, ParameterSetName = "GroupName")]
    [ValidateNotNullOrEmpty()]
    [string]$GroupName,
    [Parameter(Position = 2, ParameterSetName = "GroupId")]
    [Parameter(Position = 2, ParameterSetName = "GroupName")]
    [ValidateSet(
        "member",
        "owner"
    )]
    [string]$RoleType = "member",
    [Parameter(Position = 3, ParameterSetName = "GroupId")]
    [Parameter(Position = 3, ParameterSetName = "GroupName")]
    [System.DateTimeOffset]$StartsOn = [System.DateTimeOffset]::Parse([System.DateTimeOffset]::Now.ToString("yyyy-MM-dd 00:00:00 zzz")),
    [Parameter(Position = 4, ParameterSetName = "GroupId")]
    [Parameter(Position = 4, ParameterSetName = "GroupName")]
    [System.DateTimeOffset]$ExpiresOn = [System.DateTimeOffset]::Now.AddMonths(6),
    [Parameter(Position = 5, ParameterSetName = "GroupId")]
    [Parameter(Position = 5, ParameterSetName = "GroupName")]
    [ValidateSet(
        "Eligible",
        "Active"
    )]
    [string]$AssignmentType = "Eligible",
    [Parameter(Position = 6, ParameterSetName = "GroupId")]
    [Parameter(Position = 6, ParameterSetName = "GroupName")]
    [string]$Justification
)

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

# Get the group.
$group = $null
try {
    switch ($PSCmdlet.ParameterSetName) {
        "GroupName" {
            $group = Get-MgGroup -Filter "displayName eq '$($GroupName)'" -ErrorAction "Stop" -PageSize 1

            if ($null -eq $group -or ($group | Measure-Object).Count -eq 0) {
                throw [System.InvalidOperationException]::new("Could not find a group named '$($GroupName)'.")
            }

            break
        }

        Default {
            $group = Get-MgGroup -GroupId $GroupId -ErrorAction "Stop"
            break
        }
    }

    if (!$group.IsAssignableToRole) {
        throw [System.InvalidOperationException]::new("The group, '$($group.DisplayName)', is not assignable to a role.")
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

# Define the schedule request.
$scheduleInfo = [Microsoft.Graph.Beta.PowerShell.Models.MicrosoftGraphRequestSchedule]::new()
$scheduleInfo.StartDateTime = $StartsOn.UtcDateTime
$scheduleInfo.Expiration.Type = "afterDateTime"
$scheduleInfo.Expiration.EndDateTime = $ExpiresOn.UtcDateTime

$scheduleRequestSplat = @{
    "GroupId"      = $group.Id;
    "PrincipalId"  = $user.Id;
    "Action"       = "adminAssign";
    "AccessId"     = $RoleType;
    "ScheduleInfo" = $scheduleInfo;
}

# Add the justification, if it is provided.
if ($null -ne $Justification -and ![string]::IsNullOrWhiteSpace($Justification)) {
    $scheduleRequestSplat.Add("Justification", $Justification)
}

Write-Verbose "Assignment will start on: $($StartsOn.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss zzz"))"
Write-Verbose "Assignment will expire on: $($ExpiresOn.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss zzz"))"

# Assign the user to the group.
try {
    switch ($AssignmentType) {
        "Active" {
            if ($PSCmdlet.ShouldProcess($group.DisplayName, "Assign active role for '$($user.UserPrincipalName)'")) {
                New-MgBetaIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest @scheduleRequestSplat -ErrorAction "Stop"
            }
            break
        }

        Default {
            if ($PSCmdlet.ShouldProcess($group.DisplayName, "Assign eligible role for '$($user.UserPrincipalName)'")) {
                New-MgBetaIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest @scheduleRequestSplat -ErrorAction "Stop"
            }
            break
        }
    }
}
catch [System.Exception] {
    $errorDetails = $PSItem

    $PSCmdlet.ThrowTerminatingError($errorDetails)
}
