Find-Module Microsoft.Graph | Select-Object Name
Get-Command -Module Microsoft.Graph *License*
Get-Command -Module Microsoft.Graph *Application*
Get-Command -Module Microsoft.Graph *Team*
Connect-MgGraph -Scopes "User.Read.All", "Group.ReadWrite.All", "Directory.ReadWrite.All",
"Application.ReadWrite.All", "Team.ReadBasic.All", "TeamMember.ReadWrite.All"
Find-MgGraphPermission
Get-MgUser -Filter "StartsWith(DisplayName, 'James')" -All
Disconnect-MgGraph

