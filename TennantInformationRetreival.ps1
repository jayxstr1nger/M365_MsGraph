#Retrieves information about the Microsoft 365 tenant, including organization details, assigned plans, applications, and service principals.
Get-MgOrganization | Select-Object DisplayName, Id, TenantId

#Retrieve all assigned plans for the organization (licenses and services)
Get-MgOrganization | Select-Object -Expand AssignedPlans

#Retrieve all applications registered in the tenant
Get-MgApplication | Select-Object DisplayName, Id, AppId, SignInAudience

#Retrieve all service principals in the tenant
Get-MgServicePrincipal | Select-Object AppDisplayName, Id, AppId

