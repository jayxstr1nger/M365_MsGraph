<#PSScriptInfo

.VERSION 1.0.0

.GUID 297f46a4-d3c8-4a7a-b185-6cd85280a5c8

.AUTHOR Tim Small

.COMPANYNAME Smalls.Online

.COPYRIGHT 2026

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
    Add a user to an Entra ID role.
.DESCRIPTION
    Add a user to an Entra ID role.
.PARAMETER UserId
    The ID or UserPrincipalName of the user in Entra ID.
.PARAMETER RoleId
    The ID of the role in Entra ID.
.PARAMETER RoleName
    The name of the group in Entra ID.
.PARAMETER DirectoryScopeId
    Identifier of the directory object representing the scope of the assignment.
.PARAMETER AppScopeId
    Identifier of the app-specific scope when the assignment scope is app-specific. 
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
    Microsoft.Graph.Beta.PowerShell.Models.MicrosoftGraphUnifiedRoleAssignmentScheduleRequest
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = "RoleId")]
param(
    [Parameter(Position = 0, Mandatory, ParameterSetName = "RoleId")]
    [Parameter(Position = 0, Mandatory, ParameterSetName = "RoleName")]
    [ValidateNotNullOrEmpty()]
    [string]$UserId,
    [Parameter(Position = 1, Mandatory, ParameterSetName = "RoleId")]
    [ValidateNotNullOrEmpty()]
    [string]$RoleId,
    [Parameter(Position = 1, Mandatory, ParameterSetName = "RoleName")]
    [ValidateNotNullOrEmpty()]
    [string]$RoleName,
    [Parameter(Position = 2, ParameterSetName = "RoleId")]
    [Parameter(Position = 2, ParameterSetName = "RoleName")]
    [string]$DirectoryScopeId = "/",
    [Parameter(Position = 3, ParameterSetName = "RoleId")]
    [Parameter(Position = 3, ParameterSetName = "RoleName")]
    [string]$AppScopeId = "/",
    [Parameter(Position = 4, ParameterSetName = "RoleId")]
    [Parameter(Position = 4, ParameterSetName = "RoleName")]
    [System.DateTimeOffset]$StartsOn = [System.DateTimeOffset]::Parse([System.DateTimeOffset]::Now.ToString("yyyy-MM-dd 00:00:00 zzz")),
    [Parameter(Position = 5, ParameterSetName = "RoleId")]
    [Parameter(Position = 5, ParameterSetName = "RoleName")]
    [System.DateTimeOffset]$ExpiresOn = [System.DateTimeOffset]::Now.AddMonths(6),
    [Parameter(Position = 6, ParameterSetName = "RoleId")]
    [Parameter(Position = 6, ParameterSetName = "RoleName")]
    [ValidateSet(
        "Eligible",
        "Active"
    )]
    [string]$AssignmentType = "Eligible",
    [Parameter(Position = 7, ParameterSetName = "RoleId")]
    [Parameter(Position = 7, ParameterSetName = "RoleName")]
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
    "User.Read.All"
)

Write-Verbose -Message "Checking for required MS Graph scopes: $($requiredGraphScopes -join ", ")"
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

# Check if at least one of the required directory role scopes
# are present for the Microsoft Graph API.
$requiredOneOfDirectoryRoleGraphScopes = @(
    "RoleManagement.Read.Directory",
    "Directory.Read.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory"
)
$hasRequiredOneOfDirectoryRoleGraphScopes = $false

Write-Verbose -Message "Checking for at least one of the following directory role MS Graph scopes: $($requiredOneOfDirectoryRoleGraphScopes -join ", ")"
foreach ($scopeItem in $requiredOneOfDirectoryRoleGraphScopes) {
    $hasRequiredOneOfDirectoryRoleGraphScopes = $scopeItem -in $mgContext.Scopes

    if ($hasRequiredOneOfDirectoryRoleGraphScopes) {
        break
    }
}

if (!$hasRequiredOneOfDirectoryRoleGraphScopes) {
    $PSCmdlet.ThrowTerminatingError(
        [System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new("Please run 'Connect-MgGraph' with at least this scope: RoleManagement.Read.Directory"),
            "NotAuthenticatedToGraph",
            [System.Management.Automation.ErrorCategory]::AuthenticationError,
            $null
        )
    )
}

# Check if at least one of the required role assignment scopes
# are present for the Microsoft Graph API.
$requiredOneOfRoleAssignmentGraphScopes = @(
    "RoleAssignmentSchedule.ReadWrite.Directory",
    "RoleManagement.ReadWrite.Directory",
    "RoleAssignmentSchedule.Remove.Directory",
    "RoleEligibilitySchedule.Remove.Directory"
)
$hasRequiredOneOfRoleAssignmentGraphScopes = $false

Write-Verbose -Message "Checking for at least one of the following role assignment MS Graph scopes: $($requiredOneOfRoleAssignmentGraphScopes -join ", ")"
foreach ($scopeItem in $requiredOneOfRoleAssignmentGraphScopes) {
    $hasRequiredOneOfRoleAssignmentGraphScopes = $scopeItem -in $mgContext.Scopes

    if ($hasRequiredOneOfRoleAssignmentGraphScopes) {
        break
    }
}

if (!$hasRequiredOneOfRoleAssignmentGraphScopes) {
    $PSCmdlet.ThrowTerminatingError(
        [System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new("Please run 'Connect-MgGraph' with at least this scope: RoleAssignmentSchedule.ReadWrite.Directory"),
            "NotAuthenticatedToGraph",
            [System.Management.Automation.ErrorCategory]::AuthenticationError,
            $null
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

# Get the role.
$role = $null
try {
    switch ($PSCmdlet.ParameterSetName) {
        "RoleName" {
            $role = Get-MgDirectoryRole -Filter "displayName eq '$($RoleName)'" -ErrorAction "Stop"

            if ($null -eq $role -or ($role | Measure-Object).Count -eq 0) {
                throw [System.InvalidOperationException]::new("Could not find a role named '$($RoleName)'.")
            }

            break
        }

        Default {
            $role = Get-MgDirectoryRole -DirectoryRoleId $RoleId -ErrorAction "Stop"
            break
        }
    }
}
catch [System.Exception] {
    $ex = $PSItem.Exception

    $PSCmdlet.ThrowTerminatingError(
        [System.Management.Automation.ErrorRecord]::new(
            $ex,
            "GetRoleFailed",
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
    "RoleDefinitionId" = $role.RoleTemplateId;
    "PrincipalId"      = $user.Id;
    "DirectoryScopeId" = $DirectoryScopeId;
    "AppScopeId"       = $AppScopeId;
    "Action"           = "AdminAssign";
    "ScheduleInfo"     = $scheduleInfo;
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
            if ($PSCmdlet.ShouldProcess($role.DisplayName, "Assign active role for '$($user.UserPrincipalName)'")) {
                New-MgBetaRoleManagementDirectoryRoleAssignmentScheduleRequest @scheduleRequestSplat -ErrorAction "Stop"
            }
            break
        }

        Default {
            if ($PSCmdlet.ShouldProcess($role.DisplayName, "Assign eligible role for '$($user.UserPrincipalName)'")) {
                New-MgBetaRoleManagementDirectoryRoleEligibilityScheduleRequest @scheduleRequestSplat -ErrorAction "Stop"
            }
            break
        }
    }
}
catch [System.Exception] {
    $errorDetails = $PSItem

    $PSCmdlet.ThrowTerminatingError($errorDetails)
}
